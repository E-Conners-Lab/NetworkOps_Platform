"""
Command validation policy for network devices.

Extracted from dashboard/api_server.py to share between the Flask API
and the MCP tool layer. Contains blocked commands, shell character
filtering, and permission-based command validation.
"""

import re


# Destructive commands blocked regardless of role
BLOCKED_COMMANDS = [
    # Cisco IOS-XE destructive commands
    'reload', 'write erase', 'erase', 'format',
    'license boot', 'boot system', 'config replace', 'archive config',
    'clear counters', 'clear ip', 'clear arp', 'clear line',
    'debug', 'undebug', 'squeeze',

    # Juniper Junos destructive commands
    'request system reboot', 'request system power-off', 'request system halt',
    'request system zeroize', 'file delete', 'request system storage cleanup',
    'clear security', 'clear bgp neighbor', 'rollback',

    # HPE Aruba CX (AOS-CX) destructive commands
    'erase startup-config', 'erase all', 'copy startup-config',
    'write memory', 'clear logging',

    # HPE ProCurve destructive commands
    'erase flash', 'boot set-default',

    # HPE Comware destructive commands
    'reset saved-configuration', 'startup saved-configuration',
    'undo startup saved-configuration', 'backup startup-configuration',

    # Linux destructive commands
    'rm ', 'rm -', 'rmdir', 'mkfs', 'dd ', 'shred',
    'shutdown', 'reboot', 'halt', 'poweroff', 'init ',
    'kill ', 'killall', 'pkill',
    'chmod 777', 'chmod -R', 'chown -R',
    'mv /', 'cp /', 'wget ', 'curl -o', 'curl -O',
    'apt ', 'yum ', 'dnf ', 'apk add', 'pip install',
    'systemctl stop', 'systemctl disable', 'service stop',
    'iptables -F', 'iptables -X', 'ip link delete', 'ip route del',
    'passwd', 'useradd', 'userdel', 'usermod', 'groupadd', 'groupdel',
    'crontab', 'at ', 'nohup',

    # Nokia SR Linux destructive
    'tools system reboot', 'commit',
]

# Shell metacharacters that indicate command injection (substring match)
BLOCKED_SHELL_CHARS = [
    ';',      # Command separator
    '&&',     # AND operator
    '||',     # OR operator
    '|',      # Pipe
    '`',      # Command substitution (backticks)
    '$(',     # Command substitution
    '${',     # Variable expansion
    '>',      # Redirect output
    '>>',     # Append output
    '<',      # Redirect input
    '\n',     # Newline (command separator)
    '\r',     # Carriage return
    '%0a',    # URL-encoded newline
    '%0d',    # URL-encoded carriage return
]

# Commands allowed for operator role (read-only across all platforms)
OPERATOR_ALLOWED_PREFIXES = [
    # Cisco IOS-XE (also works for Juniper and HPE Aruba/ProCurve)
    'show', 'ping', 'traceroute',

    # Juniper Junos (most use 'show' but these are Junos-specific)
    'monitor', 'request support',

    # HPE Comware (uses 'display' instead of 'show')
    'display', 'tracert',

    # Linux
    'ip ', 'ip addr', 'ip route', 'ip link', 'ip neigh',
    'cat ', 'uptime', 'free', 'df', 'uname', 'hostname', 'whoami', 'ps', 'top -b', 'netstat', 'ss ',

    # Nokia SR Linux
    'info',
]


def validate_command(command: str, permissions: list[str]) -> tuple[bool, str | None]:
    """Validate a command against user permissions and security policy.

    Args:
        command: The command string to validate.
        permissions: List of permission names the user has.

    Returns:
        (is_valid, error_message) -- error_message is None when valid.
    """
    if not command or not isinstance(command, str):
        return False, "Invalid command"

    # Length limit to prevent DoS
    if len(command) > 1000:
        return False, "Command exceeds maximum length (1000 characters)"

    command_lower = command.lower().strip()

    # SECURITY: Block shell metacharacters (substring match - no word boundary)
    for char in BLOCKED_SHELL_CHARS:
        if char in command_lower:
            return False, f"Command contains blocked character/sequence: '{char}'"

    # Block dangerous commands (word boundary match to avoid false positives)
    for blocked in BLOCKED_COMMANDS:
        if re.search(r'\b' + re.escape(blocked) + r'\b', command_lower):
            return False, f"Command '{blocked}' is blocked for security reasons"

    # Check if this is a show-type command (read-only)
    is_show_command = any(
        command_lower.startswith(prefix) for prefix in OPERATOR_ALLOWED_PREFIXES
    )

    if is_show_command:
        if 'run_show_commands' not in permissions:
            return False, "Permission denied: requires 'run_show_commands' permission"
    else:
        if 'run_config_commands' not in permissions:
            return False, "Permission denied: requires 'run_config_commands' permission"

    return True, None


def validate_multiline_commands(
    commands: str, permissions: list[str]
) -> tuple[bool, str | None]:
    """Validate multi-line commands (e.g. config snippets) line by line.

    Whitespace-only lines and IOS comments (lines starting with '!') are skipped.

    Args:
        commands: Newline-separated command string.
        permissions: List of permission names the user has.

    Returns:
        (is_valid, error_message) -- error_message is None when all lines pass.
    """
    for line in commands.strip().split('\n'):
        line = line.strip()
        if not line or line.startswith('!'):
            continue
        valid, error = validate_command(line, permissions)
        if not valid:
            return False, f"Line '{line}': {error}"
    return True, None
