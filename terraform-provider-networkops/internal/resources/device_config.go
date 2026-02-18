// Copyright (c) 2025 NetworkOps
// SPDX-License-Identifier: MPL-2.0

package resources

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/networkops/terraform-provider-networkops/internal/provider"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &DeviceConfigResource{}
var _ resource.ResourceWithImportState = &DeviceConfigResource{}

// NewDeviceConfigResource creates a new device config resource.
func NewDeviceConfigResource() resource.Resource {
	return &DeviceConfigResource{}
}

// DeviceConfigResource defines the resource implementation.
type DeviceConfigResource struct {
	client *provider.Client
}

// DeviceConfigResourceModel describes the resource data model.
type DeviceConfigResourceModel struct {
	ID            types.String `tfsdk:"id"`
	Device        types.String `tfsdk:"device"`
	Commands      types.List   `tfsdk:"commands"`
	CommandString types.String `tfsdk:"command_string"`
	ConfigHash    types.String `tfsdk:"config_hash"`
	LastApplied   types.String `tfsdk:"last_applied"`
	Output        types.String `tfsdk:"output"`
}

// Metadata returns the resource type name.
func (r *DeviceConfigResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_device_config"
}

// Schema defines the schema for the resource.
func (r *DeviceConfigResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "Manages configuration on a network device.",
		MarkdownDescription: "Applies configuration commands to a network device. Commands are applied in order and tracked by hash for change detection.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description:         "Unique identifier for the resource (device:hash).",
				MarkdownDescription: "Unique identifier for the resource (`device:hash`).",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"device": schema.StringAttribute{
				Description:         "Device name to configure.",
				MarkdownDescription: "Device name to configure (e.g., `R1`).",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"commands": schema.ListAttribute{
				Description:         "List of configuration commands to apply.",
				MarkdownDescription: "List of configuration commands to apply in order.",
				Optional:            true,
				ElementType:         types.StringType,
			},
			"command_string": schema.StringAttribute{
				Description:         "Configuration commands as a multi-line string (alternative to commands list).",
				MarkdownDescription: "Configuration commands as a multi-line string (alternative to `commands` list).",
				Optional:            true,
			},
			"config_hash": schema.StringAttribute{
				Description:         "SHA256 hash of the configuration for change detection.",
				MarkdownDescription: "SHA256 hash of the configuration for change detection.",
				Computed:            true,
			},
			"last_applied": schema.StringAttribute{
				Description:         "Timestamp of when the configuration was last applied.",
				MarkdownDescription: "Timestamp of when the configuration was last applied.",
				Computed:            true,
			},
			"output": schema.StringAttribute{
				Description:         "Output from the configuration commands.",
				MarkdownDescription: "Output from the configuration commands.",
				Computed:            true,
			},
		},
	}
}

// Configure adds the provider configured client to the resource.
func (r *DeviceConfigResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*provider.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *provider.Client, got: %T.", req.ProviderData),
		)
		return
	}

	r.client = client
}

// Create creates the resource and sets the initial Terraform state.
func (r *DeviceConfigResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data DeviceConfigResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	deviceName := data.Device.ValueString()
	commands := r.getCommands(ctx, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Applying configuration to device", map[string]interface{}{
		"device":   deviceName,
		"commands": len(commands),
	})

	// Apply configuration
	output, err := r.client.SendConfig(ctx, deviceName, commands)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Apply Configuration",
			fmt.Sprintf("Could not apply configuration to device %s: %s", deviceName, err.Error()),
		)
		return
	}

	// Calculate hash of commands
	hash := r.hashCommands(commands)

	// Set resource data
	data.ID = types.StringValue(fmt.Sprintf("%s:%s", deviceName, hash[:8]))
	data.ConfigHash = types.StringValue(hash)
	data.LastApplied = types.StringValue(time.Now().UTC().Format(time.RFC3339))
	data.Output = types.StringValue(output)

	tflog.Debug(ctx, "Applied configuration", map[string]interface{}{
		"device": deviceName,
		"id":     data.ID.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read refreshes the Terraform state with the latest data.
func (r *DeviceConfigResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data DeviceConfigResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Device config is stateless - we don't read back from device
	// The state represents what was applied, not current device state
	// To detect drift, users should use data sources

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Update updates the resource and sets the updated Terraform state.
func (r *DeviceConfigResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data DeviceConfigResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	deviceName := data.Device.ValueString()
	commands := r.getCommands(ctx, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Updating configuration on device", map[string]interface{}{
		"device":   deviceName,
		"commands": len(commands),
	})

	// Apply updated configuration
	output, err := r.client.SendConfig(ctx, deviceName, commands)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Update Configuration",
			fmt.Sprintf("Could not update configuration on device %s: %s", deviceName, err.Error()),
		)
		return
	}

	// Calculate new hash
	hash := r.hashCommands(commands)

	// Update resource data
	data.ID = types.StringValue(fmt.Sprintf("%s:%s", deviceName, hash[:8]))
	data.ConfigHash = types.StringValue(hash)
	data.LastApplied = types.StringValue(time.Now().UTC().Format(time.RFC3339))
	data.Output = types.StringValue(output)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Delete deletes the resource and removes the Terraform state.
func (r *DeviceConfigResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data DeviceConfigResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Config resources are stateless - we can't "undo" applied config
	// Just remove from state. Users can use backup/rollback if needed.
	tflog.Debug(ctx, "Removing device config from state", map[string]interface{}{
		"device": data.Device.ValueString(),
		"id":     data.ID.ValueString(),
	})
}

// ImportState imports an existing resource into Terraform.
func (r *DeviceConfigResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import format: device_name
	// We can't know what commands were applied, so just set the device
	deviceName := req.ID

	data := DeviceConfigResourceModel{
		ID:          types.StringValue(fmt.Sprintf("%s:imported", deviceName)),
		Device:      types.StringValue(deviceName),
		ConfigHash:  types.StringValue("imported"),
		LastApplied: types.StringValue(time.Now().UTC().Format(time.RFC3339)),
		Output:      types.StringValue(""),
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// getCommands extracts commands from either list or string attribute.
func (r *DeviceConfigResource) getCommands(ctx context.Context, data *DeviceConfigResourceModel, diags *resource.CreateResponse) []string {
	var commands []string

	// Check command_string first
	if !data.CommandString.IsNull() && data.CommandString.ValueString() != "" {
		lines := strings.Split(data.CommandString.ValueString(), "\n")
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" {
				commands = append(commands, trimmed)
			}
		}
		return commands
	}

	// Otherwise use commands list
	if !data.Commands.IsNull() {
		var cmdList []string
		data.Commands.ElementsAs(ctx, &cmdList, false)
		return cmdList
	}

	return commands
}

// hashCommands creates a SHA256 hash of the commands.
func (r *DeviceConfigResource) hashCommands(commands []string) string {
	h := sha256.New()
	for _, cmd := range commands {
		h.Write([]byte(cmd))
		h.Write([]byte("\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}
