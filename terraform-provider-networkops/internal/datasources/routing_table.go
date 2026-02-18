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
var _ datasource.DataSource = &RoutingTableDataSource{}

// NewRoutingTableDataSource creates a new routing table data source.
func NewRoutingTableDataSource() datasource.DataSource {
	return &RoutingTableDataSource{}
}

// RoutingTableDataSource defines the data source implementation.
type RoutingTableDataSource struct {
	client *provider.Client
}

// RoutingTableDataSourceModel describes the data source data model.
type RoutingTableDataSourceModel struct {
	Device   types.String `tfsdk:"device"`
	Protocol types.String `tfsdk:"protocol"`
	Routes   []RouteModel `tfsdk:"routes"`
}

// RouteModel describes a routing table entry.
type RouteModel struct {
	Network        types.String `tfsdk:"network"`
	Mask           types.String `tfsdk:"mask"`
	NextHop        types.String `tfsdk:"next_hop"`
	Interface      types.String `tfsdk:"interface"`
	Protocol       types.String `tfsdk:"protocol"`
	Metric         types.Int64  `tfsdk:"metric"`
	AdminDistance  types.Int64  `tfsdk:"admin_distance"`
}

// Metadata returns the data source type name.
func (d *RoutingTableDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_routing_table"
}

// Schema defines the schema for the data source.
func (d *RoutingTableDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "Retrieves the routing table from a network device.",
		MarkdownDescription: "Retrieves the routing table from a network device, with optional protocol filtering.",

		Attributes: map[string]schema.Attribute{
			"device": schema.StringAttribute{
				Description:         "Device name to query.",
				MarkdownDescription: "Device name to query (e.g., `R1`).",
				Required:            true,
			},
			"protocol": schema.StringAttribute{
				Description:         "Optional routing protocol filter (ospf, bgp, eigrp, static, connected).",
				MarkdownDescription: "Optional routing protocol filter (`ospf`, `bgp`, `eigrp`, `static`, `connected`).",
				Optional:            true,
			},
			"routes": schema.ListNestedAttribute{
				Description:         "List of routing table entries.",
				MarkdownDescription: "List of routing table entries.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"network": schema.StringAttribute{
							Description: "Destination network.",
							Computed:    true,
						},
						"mask": schema.StringAttribute{
							Description: "Network mask.",
							Computed:    true,
						},
						"next_hop": schema.StringAttribute{
							Description: "Next hop IP address.",
							Computed:    true,
						},
						"interface": schema.StringAttribute{
							Description: "Outgoing interface.",
							Computed:    true,
						},
						"protocol": schema.StringAttribute{
							Description: "Routing protocol.",
							Computed:    true,
						},
						"metric": schema.Int64Attribute{
							Description: "Route metric.",
							Computed:    true,
						},
						"admin_distance": schema.Int64Attribute{
							Description: "Administrative distance.",
							Computed:    true,
						},
					},
				},
			},
		},
	}
}

// Configure adds the provider configured client to the data source.
func (d *RoutingTableDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
func (d *RoutingTableDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data RoutingTableDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	deviceName := data.Device.ValueString()
	protocol := ""
	if !data.Protocol.IsNull() {
		protocol = data.Protocol.ValueString()
	}

	tflog.Debug(ctx, "Reading routing table", map[string]interface{}{
		"device":   deviceName,
		"protocol": protocol,
	})

	routes, err := d.client.GetRoutingTable(ctx, deviceName, protocol)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Read Routing Table",
			fmt.Sprintf("Could not read routing table for device %s: %s", deviceName, err.Error()),
		)
		return
	}

	// Map routes
	data.Routes = make([]RouteModel, len(routes))
	for i, route := range routes {
		data.Routes[i] = RouteModel{
			Network:       types.StringValue(route.Network),
			Mask:          types.StringValue(route.Mask),
			NextHop:       types.StringValue(route.NextHop),
			Interface:     types.StringValue(route.Interface),
			Protocol:      types.StringValue(route.Protocol),
			Metric:        types.Int64Value(int64(route.Metric)),
			AdminDistance: types.Int64Value(int64(route.AD)),
		}
	}

	tflog.Debug(ctx, "Read routing table", map[string]interface{}{
		"device": deviceName,
		"routes": len(routes),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
