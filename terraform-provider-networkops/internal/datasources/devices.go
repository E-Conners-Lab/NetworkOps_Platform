// Copyright (c) 2025 NetworkOps
// SPDX-License-Identifier: MPL-2.0

package datasources

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/networkops/terraform-provider-networkops/internal/provider"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ datasource.DataSource = &DevicesDataSource{}

// NewDevicesDataSource creates a new devices data source.
func NewDevicesDataSource() datasource.DataSource {
	return &DevicesDataSource{}
}

// DevicesDataSource defines the data source implementation.
type DevicesDataSource struct {
	client *provider.Client
}

// DevicesDataSourceModel describes the data source data model.
type DevicesDataSourceModel struct {
	Devices []DeviceModel `tfsdk:"devices"`
	Filter  types.String  `tfsdk:"filter"`
}

// DeviceModel describes a single device.
type DeviceModel struct {
	Name     types.String `tfsdk:"name"`
	Host     types.String `tfsdk:"host"`
	Platform types.String `tfsdk:"platform"`
	Type     types.String `tfsdk:"type"`
}

// Metadata returns the data source type name.
func (d *DevicesDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_devices"
}

// Schema defines the schema for the data source.
func (d *DevicesDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "Retrieves the list of all network devices from the NetworkOps inventory.",
		MarkdownDescription: "Retrieves the list of all network devices from the NetworkOps inventory.",

		Attributes: map[string]schema.Attribute{
			"filter": schema.StringAttribute{
				Description:         "Optional filter to match device names or types (supports wildcards).",
				MarkdownDescription: "Optional filter to match device names or types (supports wildcards).",
				Optional:            true,
			},
			"devices": schema.ListNestedAttribute{
				Description:         "List of network devices.",
				MarkdownDescription: "List of network devices.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							Description:         "Device name (e.g., R1, Switch-R1).",
							MarkdownDescription: "Device name (e.g., `R1`, `Switch-R1`).",
							Computed:            true,
						},
						"host": schema.StringAttribute{
							Description:         "Device IP address or hostname.",
							MarkdownDescription: "Device IP address or hostname.",
							Computed:            true,
						},
						"platform": schema.StringAttribute{
							Description:         "Device platform (e.g., cisco_xe, linux, nokia_srl).",
							MarkdownDescription: "Device platform (e.g., `cisco_xe`, `linux`, `nokia_srl`).",
							Computed:            true,
						},
						"type": schema.StringAttribute{
							Description:         "Device type for connection handling.",
							MarkdownDescription: "Device type for connection handling.",
							Computed:            true,
						},
					},
				},
			},
		},
	}
}

// Configure adds the provider configured client to the data source.
func (d *DevicesDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*provider.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *provider.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	d.client = client
}

// Read refreshes the Terraform state with the latest data.
func (d *DevicesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data DevicesDataSourceModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Reading devices from NetworkOps API")

	// Call API
	devices, err := d.client.GetDevices(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Read Devices",
			"Could not read devices from NetworkOps API: "+err.Error(),
		)
		return
	}

	// Map response to model
	data.Devices = make([]DeviceModel, len(devices))
	for i, device := range devices {
		data.Devices[i] = DeviceModel{
			Name:     types.StringValue(device.Name),
			Host:     types.StringValue(device.Host),
			Platform: types.StringValue(device.Platform),
			Type:     types.StringValue(device.Type),
		}
	}

	tflog.Debug(ctx, "Read devices", map[string]interface{}{
		"count": len(devices),
	})

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
