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
var _ datasource.DataSource = &TopologyDataSource{}

// NewTopologyDataSource creates a new topology data source.
func NewTopologyDataSource() datasource.DataSource {
	return &TopologyDataSource{}
}

// TopologyDataSource defines the data source implementation.
type TopologyDataSource struct {
	client *provider.Client
}

// TopologyDataSourceModel describes the data source data model.
type TopologyDataSourceModel struct {
	Nodes []TopologyNodeModel `tfsdk:"nodes"`
	Links []TopologyLinkModel `tfsdk:"links"`
}

// TopologyNodeModel describes a topology node.
type TopologyNodeModel struct {
	ID       types.String `tfsdk:"id"`
	Name     types.String `tfsdk:"name"`
	Type     types.String `tfsdk:"type"`
	Platform types.String `tfsdk:"platform"`
	IP       types.String `tfsdk:"ip"`
	Status   types.String `tfsdk:"status"`
}

// TopologyLinkModel describes a topology link.
type TopologyLinkModel struct {
	Source          types.String `tfsdk:"source"`
	Target          types.String `tfsdk:"target"`
	SourceInterface types.String `tfsdk:"source_interface"`
	TargetInterface types.String `tfsdk:"target_interface"`
}

// Metadata returns the data source type name.
func (d *TopologyDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_topology"
}

// Schema defines the schema for the data source.
func (d *TopologyDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "Retrieves the network topology with nodes and links.",
		MarkdownDescription: "Retrieves the network topology with nodes and links discovered via CDP/LLDP.",

		Attributes: map[string]schema.Attribute{
			"nodes": schema.ListNestedAttribute{
				Description:         "List of topology nodes (devices).",
				MarkdownDescription: "List of topology nodes (devices).",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Description: "Unique node identifier.",
							Computed:    true,
						},
						"name": schema.StringAttribute{
							Description: "Device name.",
							Computed:    true,
						},
						"type": schema.StringAttribute{
							Description: "Device type (router, switch, host).",
							Computed:    true,
						},
						"platform": schema.StringAttribute{
							Description: "Device platform.",
							Computed:    true,
						},
						"ip": schema.StringAttribute{
							Description: "Management IP address.",
							Computed:    true,
						},
						"status": schema.StringAttribute{
							Description: "Device status.",
							Computed:    true,
						},
					},
				},
			},
			"links": schema.ListNestedAttribute{
				Description:         "List of topology links (connections between devices).",
				MarkdownDescription: "List of topology links (connections between devices).",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"source": schema.StringAttribute{
							Description: "Source device name.",
							Computed:    true,
						},
						"target": schema.StringAttribute{
							Description: "Target device name.",
							Computed:    true,
						},
						"source_interface": schema.StringAttribute{
							Description: "Source interface name.",
							Computed:    true,
						},
						"target_interface": schema.StringAttribute{
							Description: "Target interface name.",
							Computed:    true,
						},
					},
				},
			},
		},
	}
}

// Configure adds the provider configured client to the data source.
func (d *TopologyDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
func (d *TopologyDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data TopologyDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Reading topology from NetworkOps API")

	topology, err := d.client.GetTopology(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Read Topology",
			"Could not read topology from NetworkOps API: "+err.Error(),
		)
		return
	}

	// Map nodes
	data.Nodes = make([]TopologyNodeModel, len(topology.Nodes))
	for i, node := range topology.Nodes {
		data.Nodes[i] = TopologyNodeModel{
			ID:       types.StringValue(node.ID),
			Name:     types.StringValue(node.Name),
			Type:     types.StringValue(node.Type),
			Platform: types.StringValue(node.Platform),
			IP:       types.StringValue(node.IP),
			Status:   types.StringValue(node.Status),
		}
	}

	// Map links
	data.Links = make([]TopologyLinkModel, len(topology.Links))
	for i, link := range topology.Links {
		data.Links[i] = TopologyLinkModel{
			Source:          types.StringValue(link.Source),
			Target:          types.StringValue(link.Target),
			SourceInterface: types.StringValue(link.SourceInterface),
			TargetInterface: types.StringValue(link.TargetInterface),
		}
	}

	tflog.Debug(ctx, "Read topology", map[string]interface{}{
		"nodes": len(topology.Nodes),
		"links": len(topology.Links),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
