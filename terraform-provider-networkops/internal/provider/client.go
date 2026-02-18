// Copyright (c) 2025 NetworkOps
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is the NetworkOps API client.
type Client struct {
	BaseURL    string
	Token      string
	Username   string
	Password   string
	HTTPClient *http.Client
}

// NewClient creates a new NetworkOps API client.
func NewClient(baseURL, token, username, password string, timeout int64) (*Client, error) {
	return &Client{
		BaseURL:  baseURL,
		Token:    token,
		Username: username,
		Password: password,
		HTTPClient: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		},
	}, nil
}

// Authenticate obtains a JWT token using username/password.
func (c *Client) Authenticate(ctx context.Context) error {
	payload := map[string]string{
		"username": c.Username,
		"password": c.Password,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal auth request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/api/auth/login", bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("auth request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authentication failed with status %d", resp.StatusCode)
	}

	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode auth response: %w", err)
	}

	c.Token = result.AccessToken
	return nil
}

// HealthCheck verifies API connectivity.
func (c *Client) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+"/api/health", nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("health check request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check failed with status %d", resp.StatusCode)
	}

	return nil
}

// doRequest performs an authenticated HTTP request.
func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// Device represents a network device.
type Device struct {
	Name     string `json:"name"`
	Host     string `json:"host"`
	Platform string `json:"platform"`
	Type     string `json:"device_type"`
}

// DeviceHealth represents device health status.
type DeviceHealth struct {
	Device      string                 `json:"device"`
	Status      string                 `json:"status"`
	Reachable   bool                   `json:"reachable"`
	Interfaces  int                    `json:"interfaces"`
	CPU         float64                `json:"cpu_percent,omitempty"`
	Memory      float64                `json:"memory_percent,omitempty"`
	Uptime      string                 `json:"uptime,omitempty"`
	LastChecked string                 `json:"last_checked"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// TopologyNode represents a node in the network topology.
type TopologyNode struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Platform string `json:"platform"`
	IP       string `json:"ip"`
	Status   string `json:"status"`
}

// TopologyLink represents a link between nodes.
type TopologyLink struct {
	Source          string `json:"source"`
	Target          string `json:"target"`
	SourceInterface string `json:"source_interface"`
	TargetInterface string `json:"target_interface"`
}

// Topology represents the network topology.
type Topology struct {
	Nodes []TopologyNode `json:"nodes"`
	Links []TopologyLink `json:"links"`
}

// Route represents a routing table entry.
type Route struct {
	Network   string `json:"network"`
	Mask      string `json:"mask"`
	NextHop   string `json:"next_hop"`
	Interface string `json:"interface"`
	Protocol  string `json:"protocol"`
	Metric    int    `json:"metric"`
	AD        int    `json:"admin_distance"`
}

// InterfaceStatus represents interface information.
type InterfaceStatus struct {
	Name         string  `json:"name"`
	Status       string  `json:"status"`
	Protocol     string  `json:"protocol"`
	IPAddress    string  `json:"ip_address,omitempty"`
	Description  string  `json:"description,omitempty"`
	Speed        string  `json:"speed,omitempty"`
	Duplex       string  `json:"duplex,omitempty"`
	MTU          int     `json:"mtu,omitempty"`
	InBytes      int64   `json:"in_bytes,omitempty"`
	OutBytes     int64   `json:"out_bytes,omitempty"`
	InErrors     int     `json:"in_errors,omitempty"`
	OutErrors    int     `json:"out_errors,omitempty"`
	Utilization  float64 `json:"utilization_percent,omitempty"`
}

// Backup represents a configuration backup.
type Backup struct {
	Device    string `json:"device"`
	Filename  string `json:"filename"`
	Label     string `json:"label,omitempty"`
	Timestamp string `json:"timestamp"`
	Size      int64  `json:"size"`
}

// GetDevices returns all devices in the inventory.
func (c *Client) GetDevices(ctx context.Context) ([]Device, error) {
	body, err := c.doRequest(ctx, "GET", "/api/devices", nil)
	if err != nil {
		return nil, err
	}

	var result struct {
		Devices []Device `json:"devices"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode devices response: %w", err)
	}

	return result.Devices, nil
}

// GetDevice returns a specific device.
func (c *Client) GetDevice(ctx context.Context, name string) (*Device, error) {
	devices, err := c.GetDevices(ctx)
	if err != nil {
		return nil, err
	}

	for _, d := range devices {
		if d.Name == name {
			return &d, nil
		}
	}

	return nil, fmt.Errorf("device %s not found", name)
}

// GetDeviceHealth returns health status for a device.
func (c *Client) GetDeviceHealth(ctx context.Context, deviceName string) (*DeviceHealth, error) {
	body, err := c.doRequest(ctx, "GET", fmt.Sprintf("/api/health/%s", deviceName), nil)
	if err != nil {
		return nil, err
	}

	var result DeviceHealth
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode health response: %w", err)
	}

	return &result, nil
}

// GetAllHealth returns health status for all devices.
func (c *Client) GetAllHealth(ctx context.Context) ([]DeviceHealth, error) {
	body, err := c.doRequest(ctx, "GET", "/api/health", nil)
	if err != nil {
		return nil, err
	}

	var result struct {
		Devices []DeviceHealth `json:"devices"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode health response: %w", err)
	}

	return result.Devices, nil
}

// GetTopology returns the network topology.
func (c *Client) GetTopology(ctx context.Context) (*Topology, error) {
	body, err := c.doRequest(ctx, "GET", "/api/topology", nil)
	if err != nil {
		return nil, err
	}

	var result Topology
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode topology response: %w", err)
	}

	return &result, nil
}

// GetRoutingTable returns the routing table for a device.
func (c *Client) GetRoutingTable(ctx context.Context, deviceName string, protocol string) ([]Route, error) {
	path := fmt.Sprintf("/api/routing-table/%s", deviceName)
	if protocol != "" {
		path += "?protocol=" + protocol
	}

	body, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var result struct {
		Routes []Route `json:"routes"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode routing table response: %w", err)
	}

	return result.Routes, nil
}

// GetInterfaceStatus returns interface status for a device.
func (c *Client) GetInterfaceStatus(ctx context.Context, deviceName, interfaceName string) (*InterfaceStatus, error) {
	body, err := c.doRequest(ctx, "GET", fmt.Sprintf("/api/interface/%s/%s", deviceName, interfaceName), nil)
	if err != nil {
		return nil, err
	}

	var result InterfaceStatus
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode interface response: %w", err)
	}

	return &result, nil
}

// SendCommand executes a show command on a device.
func (c *Client) SendCommand(ctx context.Context, deviceName, command string) (string, error) {
	payload := map[string]string{
		"device":  deviceName,
		"command": command,
	}

	body, err := c.doRequest(ctx, "POST", "/api/command", payload)
	if err != nil {
		return "", err
	}

	var result struct {
		Output string `json:"output"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("failed to decode command response: %w", err)
	}

	return result.Output, nil
}

// SendConfig applies configuration commands to a device.
func (c *Client) SendConfig(ctx context.Context, deviceName string, commands []string) (string, error) {
	payload := map[string]interface{}{
		"device":   deviceName,
		"commands": commands,
	}

	body, err := c.doRequest(ctx, "POST", "/api/config", payload)
	if err != nil {
		return "", err
	}

	var result struct {
		Output  string `json:"output"`
		Success bool   `json:"success"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("failed to decode config response: %w", err)
	}

	return result.Output, nil
}

// RemediateInterface performs an action on an interface.
func (c *Client) RemediateInterface(ctx context.Context, deviceName, interfaceName, action string) error {
	payload := map[string]string{
		"device":    deviceName,
		"interface": interfaceName,
		"action":    action,
	}

	_, err := c.doRequest(ctx, "POST", "/api/remediate", payload)
	return err
}

// CreateBackup creates a configuration backup.
func (c *Client) CreateBackup(ctx context.Context, deviceName, label string) (*Backup, error) {
	payload := map[string]string{
		"device": deviceName,
	}
	if label != "" {
		payload["label"] = label
	}

	body, err := c.doRequest(ctx, "POST", "/api/backup", payload)
	if err != nil {
		return nil, err
	}

	var result Backup
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode backup response: %w", err)
	}

	return &result, nil
}

// ListBackups lists configuration backups.
func (c *Client) ListBackups(ctx context.Context, deviceName string) ([]Backup, error) {
	path := "/api/backups"
	if deviceName != "" {
		path += "?device=" + deviceName
	}

	body, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var result struct {
		Backups []Backup `json:"backups"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode backups response: %w", err)
	}

	return result.Backups, nil
}

// RollbackConfig restores a device configuration from backup.
func (c *Client) RollbackConfig(ctx context.Context, deviceName, backupLabel string, dryRun bool) (string, error) {
	payload := map[string]interface{}{
		"device":       deviceName,
		"backup_label": backupLabel,
		"dry_run":      dryRun,
	}

	body, err := c.doRequest(ctx, "POST", "/api/rollback", payload)
	if err != nil {
		return "", err
	}

	var result struct {
		Diff    string `json:"diff"`
		Applied bool   `json:"applied"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("failed to decode rollback response: %w", err)
	}

	return result.Diff, nil
}
