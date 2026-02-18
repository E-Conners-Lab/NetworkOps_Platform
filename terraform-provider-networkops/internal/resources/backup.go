// Copyright (c) 2025 NetworkOps
// SPDX-License-Identifier: MPL-2.0

package resources

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/networkops/terraform-provider-networkops/internal/provider"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &BackupResource{}
var _ resource.ResourceWithImportState = &BackupResource{}

// NewBackupResource creates a new backup resource.
func NewBackupResource() resource.Resource {
	return &BackupResource{}
}

// BackupResource defines the resource implementation.
type BackupResource struct {
	client *provider.Client
}

// BackupResourceModel describes the resource data model.
type BackupResourceModel struct {
	ID         types.String `tfsdk:"id"`
	Device     types.String `tfsdk:"device"`
	Label      types.String `tfsdk:"label"`
	FilePath   types.String `tfsdk:"file_path"`
	CreatedAt  types.String `tfsdk:"created_at"`
	ConfigSize types.Int64  `tfsdk:"config_size"`
	ConfigHash types.String `tfsdk:"config_hash"`
}

// Metadata returns the resource type name.
func (r *BackupResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_backup"
}

// Schema defines the schema for the resource.
func (r *BackupResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "Creates a configuration backup for a network device.",
		MarkdownDescription: "Creates a configuration backup for a network device. Backups can be used for rollback or compliance purposes.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description:         "Unique identifier for the backup (device:label:timestamp).",
				MarkdownDescription: "Unique identifier for the backup.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"device": schema.StringAttribute{
				Description:         "Device name to backup.",
				MarkdownDescription: "Device name to backup (e.g., `R1`).",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"label": schema.StringAttribute{
				Description:         "Label for the backup (e.g., 'pre-change', 'daily').",
				MarkdownDescription: "Label for the backup (e.g., `pre-change`, `daily`).",
				Optional:            true,
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"file_path": schema.StringAttribute{
				Description:         "Path to the backup file on the server.",
				MarkdownDescription: "Path to the backup file on the server.",
				Computed:            true,
			},
			"created_at": schema.StringAttribute{
				Description:         "Timestamp when the backup was created.",
				MarkdownDescription: "Timestamp when the backup was created.",
				Computed:            true,
			},
			"config_size": schema.Int64Attribute{
				Description:         "Size of the configuration in bytes.",
				MarkdownDescription: "Size of the configuration in bytes.",
				Computed:            true,
			},
			"config_hash": schema.StringAttribute{
				Description:         "SHA256 hash of the configuration for integrity verification.",
				MarkdownDescription: "SHA256 hash of the configuration for integrity verification.",
				Computed:            true,
			},
		},
	}
}

// Configure adds the provider configured client to the resource.
func (r *BackupResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
func (r *BackupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data BackupResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	deviceName := data.Device.ValueString()
	label := data.Label.ValueString()
	if label == "" {
		label = time.Now().UTC().Format("20060102-150405")
	}

	tflog.Debug(ctx, "Creating backup", map[string]interface{}{
		"device": deviceName,
		"label":  label,
	})

	// Create backup
	backup, err := r.client.CreateBackup(ctx, deviceName, label)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Create Backup",
			fmt.Sprintf("Could not create backup for device %s: %s", deviceName, err.Error()),
		)
		return
	}

	// Set resource data
	data.ID = types.StringValue(fmt.Sprintf("%s:%s:%s", deviceName, label, backup.CreatedAt))
	data.Label = types.StringValue(label)
	data.FilePath = types.StringValue(backup.FilePath)
	data.CreatedAt = types.StringValue(backup.CreatedAt)
	data.ConfigSize = types.Int64Value(backup.Size)
	data.ConfigHash = types.StringValue(backup.Hash)

	tflog.Debug(ctx, "Created backup", map[string]interface{}{
		"device":    deviceName,
		"file_path": backup.FilePath,
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read refreshes the Terraform state with the latest data.
func (r *BackupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data BackupResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Verify backup still exists
	deviceName := data.Device.ValueString()
	backups, err := r.client.ListBackups(ctx, deviceName)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Read Backups",
			fmt.Sprintf("Could not list backups for device %s: %s", deviceName, err.Error()),
		)
		return
	}

	// Find our backup by file path
	found := false
	filePath := data.FilePath.ValueString()
	for _, backup := range backups {
		if backup.FilePath == filePath {
			found = true
			data.ConfigSize = types.Int64Value(backup.Size)
			data.ConfigHash = types.StringValue(backup.Hash)
			break
		}
	}

	if !found {
		// Backup was deleted externally
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Update updates the resource and sets the updated Terraform state.
func (r *BackupResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Backups are immutable - any change requires replacement
	resp.Diagnostics.AddError(
		"Backup Update Not Supported",
		"Backups are immutable. To update, the backup must be replaced.",
	)
}

// Delete deletes the resource and removes the Terraform state.
func (r *BackupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data BackupResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Note: We don't actually delete the backup file
	// Backups are kept for audit/compliance purposes
	// Just remove from Terraform state
	tflog.Debug(ctx, "Removing backup from state (file preserved)", map[string]interface{}{
		"device":    data.Device.ValueString(),
		"file_path": data.FilePath.ValueString(),
	})
}

// ImportState imports an existing resource into Terraform.
func (r *BackupResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import format: device_name:file_path
	parts := strings.SplitN(req.ID, ":", 2)
	if len(parts) != 2 {
		resp.Diagnostics.AddError(
			"Invalid Import ID",
			fmt.Sprintf("Expected format: device:file_path, got: %s", req.ID),
		)
		return
	}

	deviceName := parts[0]
	filePath := parts[1]

	// Find the backup
	backups, err := r.client.ListBackups(ctx, deviceName)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to List Backups",
			fmt.Sprintf("Could not list backups for device %s: %s", deviceName, err.Error()),
		)
		return
	}

	var foundBackup *provider.Backup
	for _, backup := range backups {
		if backup.FilePath == filePath {
			foundBackup = &backup
			break
		}
	}

	if foundBackup == nil {
		resp.Diagnostics.AddError(
			"Backup Not Found",
			fmt.Sprintf("Backup %s not found for device %s", filePath, deviceName),
		)
		return
	}

	data := BackupResourceModel{
		ID:         types.StringValue(req.ID),
		Device:     types.StringValue(deviceName),
		Label:      types.StringValue(foundBackup.Label),
		FilePath:   types.StringValue(foundBackup.FilePath),
		CreatedAt:  types.StringValue(foundBackup.CreatedAt),
		ConfigSize: types.Int64Value(foundBackup.Size),
		ConfigHash: types.StringValue(foundBackup.Hash),
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Helper type for diagnostics that works with both Create and Read responses
type diagnosticsAppender interface {
	Append(diags ...diag.Diagnostic)
}
