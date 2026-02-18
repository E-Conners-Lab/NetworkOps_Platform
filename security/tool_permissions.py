"""
MCP tool permission mapping.

Maps each tool name to the permission required to invoke it, or None
for truly public / metadata-only tools. Tools that read operational
network state (routing tables, ARP, neighbors, sessions, etc.) require
``run_show_commands``. Tools that mutate state require
``run_config_commands`` or a more specific permission.

Also identifies tools that need per-command validation (e.g. send_command,
send_config).
"""

# Tool name -> required permission (None = public / no auth needed)
TOOL_PERMISSIONS: dict[str, str | None] = {
    # ------------------------------------------------------------------
    # Device tools (device.py)
    # ------------------------------------------------------------------
    'get_devices': None,                    # metadata only (device list)
    'health_check': None,                   # reachability probe
    'health_check_all': None,               # reachability probe
    'send_command': 'run_show_commands',
    'send_config': 'run_config_commands',

    # ------------------------------------------------------------------
    # Config tools (config.py)
    # ------------------------------------------------------------------
    'backup_config': 'run_show_commands',    # reads running-config
    'list_backups': None,                    # lists local files
    'compare_configs': 'run_show_commands',  # reads config content
    'rollback_config': 'run_config_commands',
    'export_documentation': 'run_show_commands',  # reads device state
    'full_network_test': 'run_show_commands',     # runs show commands on all devices

    # ------------------------------------------------------------------
    # Operations (operations.py) — network state readers
    # ------------------------------------------------------------------
    'bulk_command': 'run_show_commands',
    'get_routing_table': 'run_show_commands',
    'get_arp_table': 'run_show_commands',
    'get_mac_table': 'run_show_commands',
    'get_neighbors': 'run_show_commands',
    'get_interface_status': 'run_show_commands',
    'remediate_interface': 'remediate_interfaces',
    'get_qos_stats': 'run_show_commands',
    'get_cpu_memory': 'run_show_commands',
    'get_active_sessions': 'run_show_commands',
    'get_aaa_config': 'run_show_commands',
    'acl_analysis': 'run_show_commands',
    'get_logs': 'run_show_commands',
    'linux_health_check': 'run_show_commands',
    'ping_sweep': 'run_show_commands',
    'traceroute': 'run_show_commands',

    # ------------------------------------------------------------------
    # Memory tools — local knowledge base, no device access
    # ------------------------------------------------------------------
    'memory_search': None,
    'memory_save': None,
    'memory_recall_device': None,
    'memory_stats': None,
    'memory_context': None,
    'memory_backup': None,
    'memory_prune': None,
    'memory_repair': None,
    'memory_maintenance': None,

    # ------------------------------------------------------------------
    # Calculators — pure computation, no device access
    # ------------------------------------------------------------------
    'calculate_tunnel_mtu': None,
    'get_mtu_scenarios': None,
    'calculate_subnet_info': None,
    'split_network': None,
    'get_subnet_reference': None,
    'convert_netmask': None,

    # ------------------------------------------------------------------
    # Scheduling
    # ------------------------------------------------------------------
    'schedule_create': 'run_config_commands',  # creates jobs that run commands
    'schedule_list': None,                     # metadata
    'schedule_get': None,                      # metadata
    'schedule_update': 'run_config_commands',
    'schedule_delete': 'run_config_commands',
    'schedule_run_now': 'run_config_commands',  # triggers execution
    'schedule_history': None,                   # read-only history
    'schedule_job_types': None,                 # metadata

    # ------------------------------------------------------------------
    # Topology — reads live device state
    # ------------------------------------------------------------------
    'discover_topology': 'run_show_commands',
    'lldp_neighbors': 'run_show_commands',
    'lldp_check_status': 'run_show_commands',
    'lldp_enable': 'run_config_commands',
    'lldp_supported_platforms': None,          # static reference data

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------
    'report_generate': 'run_show_commands',    # aggregates device data
    'report_types': None,                      # metadata

    # ------------------------------------------------------------------
    # Notifications — sends to external services
    # ------------------------------------------------------------------
    'webhook_send': 'send_notifications',
    'webhook_test': 'send_notifications',
    'webhook_list': None,                      # metadata
    'webhook_alert_device_down': 'send_notifications',
    'webhook_alert_device_recovered': 'send_notifications',
    'webhook_alert_interface_down': 'send_notifications',
    'send_notification': 'send_notifications',
    'create_ticket': 'send_notifications',

    # ------------------------------------------------------------------
    # NETCONF — reads device state via NETCONF
    # ------------------------------------------------------------------
    'get_interfaces_netconf': 'run_show_commands',
    'get_netconf_capabilities': 'run_show_commands',
    'get_bgp_neighbors_netconf': 'run_show_commands',

    # ------------------------------------------------------------------
    # SNMP — reads device metrics via SNMP
    # ------------------------------------------------------------------
    'snmp_get_oid': 'run_show_commands',
    'snmp_walk_oid': 'run_show_commands',
    'snmp_poll_metrics': 'run_show_commands',
    'snmp_poll_all_devices': 'run_show_commands',
    'snmp_list_common_oids': None,             # static OID reference

    # ------------------------------------------------------------------
    # Testing / pyATS — connects to devices
    # ------------------------------------------------------------------
    'pyats_generate_testbed': None,            # generates local file
    'pyats_learn_feature': 'run_show_commands',
    'pyats_snapshot_state': 'run_show_commands',
    'pyats_diff_state': None,                  # compares local snapshots
    'pyats_list_baselines': None,              # lists local files
    'pyats_list_templates': None,              # lists local files
    'pyats_cve_check': 'run_show_commands',    # reads device version info
    'pyats_interface_report': 'run_show_commands',
    'pyats_inventory_report': 'run_show_commands',
    'aetest_run_tests': 'run_show_commands',   # runs tests against devices
    'aetest_list_tests': None,                 # lists local test files
    'aetest_run_suite': 'run_show_commands',

    # ------------------------------------------------------------------
    # Compliance — reads device config for validation
    # ------------------------------------------------------------------
    'compliance_check': 'run_show_commands',
    'compliance_check_all': 'run_show_commands',
    'compliance_list_templates': None,         # lists local templates
    'compliance_get_template': None,           # reads local template
    'compliance_history': None,                # reads local history
    'compliance_trend': None,                  # reads local history
    'compliance_remediate': 'run_config_commands',

    # ------------------------------------------------------------------
    # Changes — change management workflow
    # ------------------------------------------------------------------
    'change_create': None,                     # creates a change request
    'change_approve': None,                    # approves a change request
    'change_execute': 'run_config_commands',
    'change_rollback': 'run_config_commands',
    'change_get': None,                        # reads change record
    'change_list': None,                       # reads change records
    'change_capture_state': 'run_show_commands',  # reads device state

    # ------------------------------------------------------------------
    # Capacity — reads device metrics
    # ------------------------------------------------------------------
    'capacity_collect': 'run_show_commands',
    'capacity_forecast_interface': None,       # local computation on collected data
    'capacity_forecast_cpu': None,             # local computation
    'capacity_trend': None,                    # local computation
    'capacity_recommendations': None,          # local computation
    'capacity_summary': None,                  # local computation

    # ------------------------------------------------------------------
    # Baselines — reads device metrics
    # ------------------------------------------------------------------
    'baseline_collect': 'run_show_commands',
    'baseline_collect_all': 'run_show_commands',
    'baseline_calculate': None,                # local computation
    'baseline_detect_anomalies': None,         # local computation
    'baseline_get_anomalies': None,            # local data
    'baseline_summary': None,                  # local data

    # ------------------------------------------------------------------
    # Events — local event store
    # ------------------------------------------------------------------
    'get_event_log': None,
    'clear_event_log': 'run_config_commands',  # destructive: clears data
    'event_collect': 'run_show_commands',       # reads device state
    'event_correlate': None,                   # local computation
    'event_incidents': None,                   # local data
    'event_incident_detail': None,             # local data
    'event_rca': None,                         # local computation
    'event_update_status': None,               # updates local record
    'event_stats': None,                       # local data

    # ------------------------------------------------------------------
    # Playbooks
    # ------------------------------------------------------------------
    'playbook_list': None,                     # lists local playbooks
    'playbook_detail': None,                   # reads local playbook
    'playbook_execute': 'run_config_commands',
    'playbook_history': None,                  # reads local history
    'playbook_execution_detail': None,         # reads local history

    # ------------------------------------------------------------------
    # Orchestration — executes on devices
    # ------------------------------------------------------------------
    'nornir_run_command': 'run_show_commands',
    'nornir_run_config': 'run_config_commands',
    'nornir_get_facts': 'run_show_commands',   # connects to devices
    'nornir_inventory': None,                  # local inventory data
    'ansible_run_playbook': 'run_config_commands',
    'ansible_list_playbooks': None,            # lists local files
    'ansible_inventory': None,                 # local inventory
    'ansible_summary': None,                   # local data
    'ansible_adhoc': 'run_show_commands',

    # ------------------------------------------------------------------
    # Feedback — local knowledge base
    # ------------------------------------------------------------------
    'feedback_record': None,
    'feedback_search': None,
    'feedback_stats': None,
    'feedback_learn': None,

    # ------------------------------------------------------------------
    # Impact analysis — reads device state
    # ------------------------------------------------------------------
    'impact_analyze': 'run_show_commands',
    'impact_status': None,                     # local cached data
    'impact_check_interface': 'run_show_commands',
    'impact_snapshot': 'run_show_commands',
    'impact_baseline_set': None,               # local data
    'impact_baseline_get': None,               # local data
    'impact_drift_check': 'run_show_commands',
    'impact_trending_summary': None,           # local computation

    # ------------------------------------------------------------------
    # Syslog — local syslog receiver
    # ------------------------------------------------------------------
    'syslog_start': 'run_config_commands',     # starts a listener
    'syslog_stop': 'run_config_commands',      # stops a listener
    'syslog_status': None,                     # local status
    'syslog_events': None,                     # reads collected events
    'syslog_summary': None,                    # local data
    'syslog_clear': 'run_config_commands',     # destructive: clears data
    'syslog_severity_levels': None,            # static reference

    # ------------------------------------------------------------------
    # Cache — local cache management
    # ------------------------------------------------------------------
    'cache_status': None,
}

# Tools that require per-command content validation (not just permission check)
COMMAND_VALIDATED_TOOLS: set[str] = {'send_command', 'send_config', 'bulk_command'}


def get_required_permission(tool_name: str) -> str | None:
    """Return the permission required to invoke a tool, or None if public.

    Tools not listed in TOOL_PERMISSIONS are treated as public (None).
    """
    return TOOL_PERMISSIONS.get(tool_name)
