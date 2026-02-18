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
var _ datasource.DataSource = &HealthDataSource{}

// NewHealthDataSource creates a new health data source.
func NewHealthDataSource() datasource.DataSource {
	return &HealthDataSource{}
}

// HealthDataSource defines the data source implementation.
type HealthDataSource struct {
	client *provider.Client
}

// HealthDataSourceModel describes the data source data model.
type HealthDataSourceModel struct {
	Device     types.String           `tfsdk:"device"`
	Devices    []DeviceHealthModel    `tfsdk:"devices"`
	AllHealthy types.Bool             `tfsdk:"all_healthy"`
	Summary    *HealthSummaryModel    `tfsdk:"summary"`
}

// DeviceHealthModel describes device health status.
type DeviceHealthModel struct {
	Name       types.String  `tfsdk:"name"`
	Status     types.String  `tfsdk:"status"`
	Reachable  types.Bool    `tfsdk:"reachable"`
	Interfaces types.Int64   `tfsdk:"interfaces"`
	CPU        types.Float64 `tfsdk:"cpu_percent"`
	Memory     types.Float64 `tfsdk:"memory_percent"`
	Uptime     types.String  `tfsdk:"uptime"`
}

// HealthSummaryModel describes overall health summary.
type HealthSummaryModel struct {
	TotalDevices   types.Int64 `tfsdk:"total_devices"`
	HealthyDevices types.Int64 `tfsdk:"healthy_devices"`
	UnhealthyDevices types.Int64 `tfsdk:"unhealthy_devices"`
}

// Metadata returns the data source type name.
func (d *HealthDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_health"
}

// Schema defines the schema for the data source.
func (d *HealthDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "Retrieves health status for network devices.",
		MarkdownDescription: "Retrieves health status for network devices, including CPU, memory, and interface counts.",

		Attributes: map[string]schema.Attribute{
			"device": schema.StringAttribute{
				Description:         "Optional specific device to check. If not set, checks all devices.",
				MarkdownDescription: "Optional specific device to check. If not set, checks all devices.",
				Optional:            true,
			},
			"all_healthy": schema.BoolAttribute{
				Description:         "Whether all devices are healthy.",
				MarkdownDescription: "Whether all devices are healthy.",
				Computed:            true,
			},
			"devices": schema.ListNestedAttribute{
				Description:         "List of device health statuses.",
				MarkdownDescription: "List of device health statuses.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							Description: "Device name.",
							Computed:    true,
						},
						"status": schema.StringAttribute{
							Description: "Health status (healthy, unhealthy, unknown).",
							Computed:    true,
						},
						"reachable": schema.BoolAttribute{
							Description: "Whether the device is reachable.",
							Computed:    true,
						},
						"interfaces": schema.Int64Attribute{
							Description: "Number of interfaces.",
							Computed:    true,
						},
						"cpu_percent": schema.Float64Attribute{
							Description: "CPU utilization percentage.",
							Computed:    true,
						},
						"memory_percent": schema.Float64Attribute{
							Description: "Memory utilization percentage.",
							Computed:    true,
						},
						"uptime": schema.StringAttribute{
							Description: "Device uptime.",
							Computed:    true,
						},
					},
				},
			},
			"summary": schema.SingleNestedAttribute{
				Description:         "Summary of health across all devices.",
				MarkdownDescription: "Summary of health across all devices.",
				Computed:            true,
				Attributes: map[string]schema.Attribute{
					"total_devices": schema.Int64Attribute{
						Description: "Total number of devices checked.",
						Computed:    true,
					},
					"healthy_devices": schema.Int64Attribute{
						Description: "Number of healthy devices.",
						Computed:    true,
					},
					"unhealthy_devices": schema.Int64Attribute{
						Description: "Number of unhealthy devices.",
						Computed:    true,
					},
				},
			},
		},
	}
}

// Configure adds the provider configured client to the data source.
func (d *HealthDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
func (d *HealthDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data HealthDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var healthResults []provider.DeviceHealth
	var err error

	if !data.Device.IsNull() && data.Device.ValueString() != "" {
		// Get health for specific device
		deviceName := data.Device.ValueString()
		tflog.Debug(ctx, "Reading health for device", map[string]interface{}{
			"device": deviceName,
		})

		health, err := d.client.GetDeviceHealth(ctx, deviceName)
		if err != nil {
			resp.Diagnostics.AddError(
				"Unable to Read Device Health",
				fmt.Sprintf("Could not read health for device %s: %s", deviceName, err.Error()),
			)
			return
		}
		healthResults = []provider.DeviceHealth{*health}
	} else {
		// Get health for all devices
		tflog.Debug(ctx, "Reading health for all devices")

		healthResults, err = d.client.GetAllHealth(ctx)
		if err != nil {
			resp.Diagnostics.AddError(
				"Unable to Read Device Health",
				"Could not read health from NetworkOps API: "+err.Error(),
			)
			return
		}
	}

	// Map response to model
	data.Devices = make([]DeviceHealthModel, len(healthResults))
	healthyCount := int64(0)
	unhealthyCount := int64(0)

	for i, health := range healthResults {
		isHealthy := health.Reachable && health.Status == "healthy"
		if isHealthy {
			healthyCount++
		} else {
			unhealthyCount++
		}

		data.Devices[i] = DeviceHealthModel{
			Name:       types.StringValue(health.Device),
			Status:     types.StringValue(health.Status),
			Reachable:  types.BoolValue(health.Reachable),
			Interfaces: types.Int64Value(int64(health.Interfaces)),
			CPU:        types.Float64Value(health.CPU),
			Memory:     types.Float64Value(health.Memory),
			Uptime:     types.StringValue(health.Uptime),
		}
	}

	data.AllHealthy = types.BoolValue(unhealthyCount == 0)
	data.Summary = &HealthSummaryModel{
		TotalDevices:     types.Int64Value(int64(len(healthResults))),
		HealthyDevices:   types.Int64Value(healthyCount),
		UnhealthyDevices: types.Int64Value(unhealthyCount),
	}

	tflog.Debug(ctx, "Read health", map[string]interface{}{
		"total":     len(healthResults),
		"healthy":   healthyCount,
		"unhealthy": unhealthyCount,
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
