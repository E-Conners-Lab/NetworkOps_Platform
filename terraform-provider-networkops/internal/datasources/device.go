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
var _ datasource.DataSource = &DeviceDataSource{}

// NewDeviceDataSource creates a new device data source.
func NewDeviceDataSource() datasource.DataSource {
	return &DeviceDataSource{}
}

// DeviceDataSource defines the data source implementation.
type DeviceDataSource struct {
	client *provider.Client
}

// DeviceDataSourceModel describes the data source data model.
type DeviceDataSourceModel struct {
	Name     types.String `tfsdk:"name"`
	Host     types.String `tfsdk:"host"`
	Platform types.String `tfsdk:"platform"`
	Type     types.String `tfsdk:"type"`
}

// Metadata returns the data source type name.
func (d *DeviceDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_device"
}

// Schema defines the schema for the data source.
func (d *DeviceDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "Retrieves information about a specific network device.",
		MarkdownDescription: "Retrieves information about a specific network device from the NetworkOps inventory.",

		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Description:         "Device name to look up.",
				MarkdownDescription: "Device name to look up (e.g., `R1`, `Switch-R1`).",
				Required:            true,
			},
			"host": schema.StringAttribute{
				Description:         "Device IP address or hostname.",
				MarkdownDescription: "Device IP address or hostname.",
				Computed:            true,
			},
			"platform": schema.StringAttribute{
				Description:         "Device platform (e.g., cisco_xe, linux).",
				MarkdownDescription: "Device platform (e.g., `cisco_xe`, `linux`).",
				Computed:            true,
			},
			"type": schema.StringAttribute{
				Description:         "Device type for connection handling.",
				MarkdownDescription: "Device type for connection handling.",
				Computed:            true,
			},
		},
	}
}

// Configure adds the provider configured client to the data source.
func (d *DeviceDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*provider.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *provider.Client, got: %T.", req.ProviderData),
		)
		return
	}

	d.client = client
}

// Read refreshes the Terraform state with the latest data.
func (d *DeviceDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data DeviceDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	deviceName := data.Name.ValueString()
	tflog.Debug(ctx, "Reading device from NetworkOps API", map[string]interface{}{
		"device": deviceName,
	})

	device, err := d.client.GetDevice(ctx, deviceName)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Read Device",
			fmt.Sprintf("Could not read device %s: %s", deviceName, err.Error()),
		)
		return
	}

	data.Name = types.StringValue(device.Name)
	data.Host = types.StringValue(device.Host)
	data.Platform = types.StringValue(device.Platform)
	data.Type = types.StringValue(device.Type)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
