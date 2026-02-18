// Copyright (c) 2025 NetworkOps
// SPDX-License-Identifier: MPL-2.0

package resources

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/networkops/terraform-provider-networkops/internal/provider"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &InterfaceResource{}
var _ resource.ResourceWithImportState = &InterfaceResource{}

// NewInterfaceResource creates a new interface resource.
func NewInterfaceResource() resource.Resource {
	return &InterfaceResource{}
}

// InterfaceResource defines the resource implementation.
type InterfaceResource struct {
	client *provider.Client
}

// InterfaceResourceModel describes the resource data model.
type InterfaceResourceModel struct {
	ID          types.String `tfsdk:"id"`
	Device      types.String `tfsdk:"device"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Enabled     types.Bool   `tfsdk:"enabled"`
	IPAddress   types.String `tfsdk:"ip_address"`
	Netmask     types.String `tfsdk:"netmask"`
	MTU         types.Int64  `tfsdk:"mtu"`
	Speed       types.String `tfsdk:"speed"`
	Duplex      types.String `tfsdk:"duplex"`
	// Read-only attributes
	OperStatus   types.String `tfsdk:"oper_status"`
	AdminStatus  types.String `tfsdk:"admin_status"`
	InOctets     types.Int64  `tfsdk:"in_octets"`
	OutOctets    types.Int64  `tfsdk:"out_octets"`
	InErrors     types.Int64  `tfsdk:"in_errors"`
	OutErrors    types.Int64  `tfsdk:"out_errors"`
}

// Metadata returns the resource type name.
func (r *InterfaceResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_interface"
}

// Schema defines the schema for the resource.
func (r *InterfaceResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "Manages a network interface on a device.",
		MarkdownDescription: "Manages a network interface on a device. Supports enabling/disabling, setting description, IP address, MTU, and other parameters.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description:         "Unique identifier for the resource (device:interface).",
				MarkdownDescription: "Unique identifier for the resource (`device:interface`).",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"device": schema.StringAttribute{
				Description:         "Device name.",
				MarkdownDescription: "Device name (e.g., `R1`).",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"name": schema.StringAttribute{
				Description:         "Interface name.",
				MarkdownDescription: "Interface name (e.g., `GigabitEthernet1`, `Loopback0`).",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"description": schema.StringAttribute{
				Description:         "Interface description.",
				MarkdownDescription: "Interface description.",
				Optional:            true,
			},
			"enabled": schema.BoolAttribute{
				Description:         "Whether the interface is administratively enabled.",
				MarkdownDescription: "Whether the interface is administratively enabled (default: `true`).",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
			},
			"ip_address": schema.StringAttribute{
				Description:         "IP address to configure on the interface.",
				MarkdownDescription: "IP address to configure on the interface.",
				Optional:            true,
			},
			"netmask": schema.StringAttribute{
				Description:         "Subnet mask for the IP address.",
				MarkdownDescription: "Subnet mask for the IP address (e.g., `255.255.255.0`).",
				Optional:            true,
			},
			"mtu": schema.Int64Attribute{
				Description:         "Maximum transmission unit.",
				MarkdownDescription: "Maximum transmission unit (default varies by interface type).",
				Optional:            true,
			},
			"speed": schema.StringAttribute{
				Description:         "Interface speed (auto, 10, 100, 1000).",
				MarkdownDescription: "Interface speed (`auto`, `10`, `100`, `1000`).",
				Optional:            true,
			},
			"duplex": schema.StringAttribute{
				Description:         "Duplex mode (auto, full, half).",
				MarkdownDescription: "Duplex mode (`auto`, `full`, `half`).",
				Optional:            true,
			},
			// Read-only attributes
			"oper_status": schema.StringAttribute{
				Description:         "Operational status of the interface.",
				MarkdownDescription: "Operational status of the interface (e.g., `up`, `down`).",
				Computed:            true,
			},
			"admin_status": schema.StringAttribute{
				Description:         "Administrative status of the interface.",
				MarkdownDescription: "Administrative status of the interface.",
				Computed:            true,
			},
			"in_octets": schema.Int64Attribute{
				Description:         "Number of octets received.",
				MarkdownDescription: "Number of octets received.",
				Computed:            true,
			},
			"out_octets": schema.Int64Attribute{
				Description:         "Number of octets sent.",
				MarkdownDescription: "Number of octets sent.",
				Computed:            true,
			},
			"in_errors": schema.Int64Attribute{
				Description:         "Number of input errors.",
				MarkdownDescription: "Number of input errors.",
				Computed:            true,
			},
			"out_errors": schema.Int64Attribute{
				Description:         "Number of output errors.",
				MarkdownDescription: "Number of output errors.",
				Computed:            true,
			},
		},
	}
}

// Configure adds the provider configured client to the resource.
func (r *InterfaceResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
func (r *InterfaceResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data InterfaceResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	deviceName := data.Device.ValueString()
	interfaceName := data.Name.ValueString()

	tflog.Debug(ctx, "Configuring interface", map[string]interface{}{
		"device":    deviceName,
		"interface": interfaceName,
	})

	// Build configuration commands
	commands := r.buildInterfaceCommands(&data)

	// Apply configuration
	_, err := r.client.SendConfig(ctx, deviceName, commands)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Configure Interface",
			fmt.Sprintf("Could not configure interface %s on device %s: %s", interfaceName, deviceName, err.Error()),
		)
		return
	}

	// Set ID
	data.ID = types.StringValue(fmt.Sprintf("%s:%s", deviceName, interfaceName))

	// Read back interface status
	r.refreshInterfaceState(ctx, &data)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read refreshes the Terraform state with the latest data.
func (r *InterfaceResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data InterfaceResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.refreshInterfaceState(ctx, &data)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Update updates the resource and sets the updated Terraform state.
func (r *InterfaceResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data InterfaceResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	deviceName := data.Device.ValueString()
	interfaceName := data.Name.ValueString()

	tflog.Debug(ctx, "Updating interface", map[string]interface{}{
		"device":    deviceName,
		"interface": interfaceName,
	})

	// Build configuration commands
	commands := r.buildInterfaceCommands(&data)

	// Apply configuration
	_, err := r.client.SendConfig(ctx, deviceName, commands)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Update Interface",
			fmt.Sprintf("Could not update interface %s on device %s: %s", interfaceName, deviceName, err.Error()),
		)
		return
	}

	// Read back interface status
	r.refreshInterfaceState(ctx, &data)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Delete deletes the resource and removes the Terraform state.
func (r *InterfaceResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data InterfaceResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	deviceName := data.Device.ValueString()
	interfaceName := data.Name.ValueString()

	tflog.Debug(ctx, "Resetting interface to defaults", map[string]interface{}{
		"device":    deviceName,
		"interface": interfaceName,
	})

	// Reset interface to defaults (remove config)
	commands := []string{
		fmt.Sprintf("default interface %s", interfaceName),
	}

	_, err := r.client.SendConfig(ctx, deviceName, commands)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Reset Interface",
			fmt.Sprintf("Could not reset interface %s on device %s: %s", interfaceName, deviceName, err.Error()),
		)
		return
	}
}

// ImportState imports an existing resource into Terraform.
func (r *InterfaceResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import format: device_name:interface_name
	parts := strings.SplitN(req.ID, ":", 2)
	if len(parts) != 2 {
		resp.Diagnostics.AddError(
			"Invalid Import ID",
			fmt.Sprintf("Expected format: device:interface, got: %s", req.ID),
		)
		return
	}

	data := InterfaceResourceModel{
		ID:      types.StringValue(req.ID),
		Device:  types.StringValue(parts[0]),
		Name:    types.StringValue(parts[1]),
		Enabled: types.BoolValue(true),
	}

	// Read current state
	r.refreshInterfaceState(ctx, &data)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// buildInterfaceCommands builds the configuration commands for the interface.
func (r *InterfaceResource) buildInterfaceCommands(data *InterfaceResourceModel) []string {
	var commands []string

	interfaceName := data.Name.ValueString()
	commands = append(commands, fmt.Sprintf("interface %s", interfaceName))

	// Description
	if !data.Description.IsNull() && data.Description.ValueString() != "" {
		commands = append(commands, fmt.Sprintf("description %s", data.Description.ValueString()))
	}

	// IP Address
	if !data.IPAddress.IsNull() && data.IPAddress.ValueString() != "" {
		netmask := "255.255.255.0"
		if !data.Netmask.IsNull() && data.Netmask.ValueString() != "" {
			netmask = data.Netmask.ValueString()
		}
		commands = append(commands, fmt.Sprintf("ip address %s %s", data.IPAddress.ValueString(), netmask))
	}

	// MTU
	if !data.MTU.IsNull() {
		commands = append(commands, fmt.Sprintf("mtu %d", data.MTU.ValueInt64()))
	}

	// Speed
	if !data.Speed.IsNull() && data.Speed.ValueString() != "" {
		if data.Speed.ValueString() == "auto" {
			commands = append(commands, "speed auto")
		} else {
			commands = append(commands, fmt.Sprintf("speed %s", data.Speed.ValueString()))
		}
	}

	// Duplex
	if !data.Duplex.IsNull() && data.Duplex.ValueString() != "" {
		commands = append(commands, fmt.Sprintf("duplex %s", data.Duplex.ValueString()))
	}

	// Enable/Disable
	if data.Enabled.ValueBool() {
		commands = append(commands, "no shutdown")
	} else {
		commands = append(commands, "shutdown")
	}

	return commands
}

// refreshInterfaceState reads the current interface state from the device.
func (r *InterfaceResource) refreshInterfaceState(ctx context.Context, data *InterfaceResourceModel) {
	deviceName := data.Device.ValueString()
	interfaceName := data.Name.ValueString()

	status, err := r.client.GetInterfaceStatus(ctx, deviceName, interfaceName)
	if err != nil {
		// Interface might not exist yet, which is OK for create
		tflog.Debug(ctx, "Could not read interface status", map[string]interface{}{
			"device":    deviceName,
			"interface": interfaceName,
			"error":     err.Error(),
		})
		return
	}

	// Update computed attributes
	data.OperStatus = types.StringValue(status.OperStatus)
	data.AdminStatus = types.StringValue(status.AdminStatus)
	data.InOctets = types.Int64Value(status.InOctets)
	data.OutOctets = types.Int64Value(status.OutOctets)
	data.InErrors = types.Int64Value(status.InErrors)
	data.OutErrors = types.Int64Value(status.OutErrors)
}
