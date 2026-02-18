#!/usr/bin/env python3
"""
Zero Touch Provisioning (ZTP) Script for Cisco IOS-XE Routers

This script configures new routers with the minimum requirements for
NetworkOps dashboard integration:
- NETCONF-YANG (required for health checks)
- LLDP (required for topology discovery)
- MDT Telemetry (optional, for real-time stats)
- Basic security hardening

Usage:
1. Host this script on an HTTP server accessible during router boot
2. Configure DHCP option 67 to point to this script
3. Router will download and execute on first boot

Tested on: Cisco C8000V, Cat9kv (IOS-XE 17.x)
"""

import os
import sys
import time

# IOS-XE provides the 'cli' module for configuration
try:
    from cli import configure, executep, cli
except ImportError:
    # For testing outside of IOS-XE
    print("ERROR: This script must run on a Cisco IOS-XE device")
    sys.exit(1)

# =============================================================================
# Configuration Variables - Customize these for your environment
# =============================================================================

# Telemetry collector (your NetworkOps server)
TELEMETRY_COLLECTOR_IP = os.getenv("TELEMETRY_COLLECTOR_IP", "203.0.113.65")
TELEMETRY_COLLECTOR_PORT = 57000

# Management credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin"  # Change in production!

# Domain and DNS
DOMAIN_NAME = "lab.local"
DNS_SERVER = "8.8.8.8"

# NTP server (optional)
NTP_SERVER = "pool.ntp.org"

# Enable telemetry subscriptions (set False for minimal config)
ENABLE_TELEMETRY = True

# =============================================================================
# Helper Functions
# =============================================================================

def log(message):
    """Print timestamped log message."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[ZTP {timestamp}] {message}")


def get_mgmt_ip():
    """Get the management IP address assigned via DHCP."""
    try:
        output = cli("show ip interface brief | include up.*up")
        # Parse first interface with IP
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1] != "unassigned":
                return parts[1]
    except Exception:
        pass
    return None


def configure_device(commands):
    """Apply configuration commands."""
    try:
        configure(commands)
        return True
    except Exception as e:
        log(f"Configuration error: {e}")
        return False


# =============================================================================
# Configuration Sections
# =============================================================================

def configure_basic():
    """Configure basic device settings."""
    log("Configuring basic settings...")

    commands = f"""
        hostname ZTP-Router
        ip domain-name {DOMAIN_NAME}
        ip name-server {DNS_SERVER}
        no ip domain-lookup
        service timestamps debug datetime msec localtime
        service timestamps log datetime msec localtime
        service password-encryption
    """

    if NTP_SERVER:
        commands += f"""
        ntp server {NTP_SERVER}
        clock timezone UTC 0
        """

    return configure_device(commands)


def configure_credentials():
    """Configure admin credentials and SSH."""
    log("Configuring credentials and SSH...")

    commands = f"""
        username {ADMIN_USERNAME} privilege 15 secret {ADMIN_PASSWORD}
        aaa new-model
        aaa authentication login default local
        aaa authorization exec default local

        crypto key generate rsa modulus 2048
        ip ssh version 2
        ip ssh time-out 60
        ip ssh authentication-retries 3

        line vty 0 15
         login local
         transport input ssh
         exec-timeout 30 0
        line console 0
         login local
         exec-timeout 30 0
    """

    return configure_device(commands)


def configure_netconf():
    """Configure NETCONF-YANG (required for dashboard health checks)."""
    log("Configuring NETCONF-YANG...")

    commands = """
        netconf-yang
        netconf-yang feature candidate-datastore
    """

    return configure_device(commands)


def configure_lldp():
    """Configure LLDP (required for topology discovery).

    LLDP is vendor-neutral and used by the dashboard to discover
    network topology across multi-vendor environments.
    """
    log("Configuring LLDP...")

    commands = """
        lldp run
        lldp holdtime 120
        lldp reinit 2
        lldp timer 30
    """

    return configure_device(commands)


def configure_telemetry():
    """Configure MDT telemetry subscriptions."""
    if not ENABLE_TELEMETRY:
        log("Telemetry disabled, skipping...")
        return True

    log("Configuring MDT telemetry...")

    # Get management IP for source-address
    mgmt_ip = get_mgmt_ip()
    if not mgmt_ip:
        log("WARNING: Could not determine management IP, using 0.0.0.0")
        mgmt_ip = "0.0.0.0"

    commands = f"""
        telemetry receiver protocol grpc-tcp

        telemetry ietf subscription 100
         encoding encode-kvgpb
         filter xpath /interfaces-ios-xe-oper:interfaces/interface/statistics
         source-address {mgmt_ip}
         stream yang-push
         update-policy periodic 5000
         receiver ip address {TELEMETRY_COLLECTOR_IP} {TELEMETRY_COLLECTOR_PORT} protocol grpc-tcp

        telemetry ietf subscription 101
         encoding encode-kvgpb
         filter xpath /process-cpu-ios-xe-oper:cpu-usage/cpu-utilization/five-seconds
         source-address {mgmt_ip}
         stream yang-push
         update-policy periodic 5000
         receiver ip address {TELEMETRY_COLLECTOR_IP} {TELEMETRY_COLLECTOR_PORT} protocol grpc-tcp

        telemetry ietf subscription 102
         encoding encode-kvgpb
         filter xpath /memory-ios-xe-oper:memory-statistics/memory-statistic
         source-address {mgmt_ip}
         stream yang-push
         update-policy periodic 5000
         receiver ip address {TELEMETRY_COLLECTOR_IP} {TELEMETRY_COLLECTOR_PORT} protocol grpc-tcp

        telemetry ietf subscription 103
         encoding encode-kvgpb
         filter xpath /interfaces-ios-xe-oper:interfaces/interface/oper-status
         stream yang-push
         update-policy on-change
         receiver ip address {TELEMETRY_COLLECTOR_IP} {TELEMETRY_COLLECTOR_PORT} protocol grpc-tcp
    """

    return configure_device(commands)


def configure_security():
    """Apply basic security hardening."""
    log("Applying security hardening...")

    commands = """
        no ip http server
        no ip http secure-server
        ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr
        ip ssh server algorithm mac hmac-sha2-256 hmac-sha2-512

        no service tcp-small-servers
        no service udp-small-servers
        no ip bootp server
        no ip source-route
        no ip finger

        logging buffered 16384 informational
        logging console informational

        banner motd ^
        ******************************************************************
        *  AUTHORIZED ACCESS ONLY - NetworkOps Managed Device           *
        *  All activity is monitored and logged.                        *
        ******************************************************************
        ^
    """

    return configure_device(commands)


def save_config():
    """Save running config to startup config."""
    log("Saving configuration...")
    try:
        cli("write memory")
        return True
    except Exception as e:
        log(f"Save error: {e}")
        return False


# =============================================================================
# Main ZTP Execution
# =============================================================================

def main():
    """Main ZTP execution flow."""
    log("=" * 60)
    log("NetworkOps ZTP Script Starting")
    log("=" * 60)

    steps = [
        ("Basic settings", configure_basic),
        ("Credentials/SSH", configure_credentials),
        ("NETCONF-YANG", configure_netconf),
        ("LLDP", configure_lldp),
        ("MDT Telemetry", configure_telemetry),
        ("Security hardening", configure_security),
        ("Save config", save_config),
    ]

    success = True
    for step_name, step_func in steps:
        log(f"Step: {step_name}")
        if not step_func():
            log(f"FAILED: {step_name}")
            success = False
            # Continue with other steps even if one fails

    log("=" * 60)
    if success:
        log("ZTP COMPLETED SUCCESSFULLY")
        log("Device is ready for NetworkOps dashboard integration")
    else:
        log("ZTP COMPLETED WITH ERRORS - Check logs above")
    log("=" * 60)

    # Wait for NETCONF to initialize (takes 2-3 minutes on first enable)
    if success:
        log("Waiting 60s for NETCONF subsystem to initialize...")
        time.sleep(60)
        log("Device ready for management")


if __name__ == "__main__":
    main()
