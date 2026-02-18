"""
Model-Driven Telemetry (MDT) gRPC Collector for Cisco IOS-XE.
Receives streaming telemetry and stores latest values for dashboard consumption.
Optionally writes to InfluxDB for long-term storage.
"""

import threading
import time
from concurrent import futures
from collections import defaultdict
from core.timestamps import isonow
import struct
import sys
import os
import logging

# Set up logging
logger = logging.getLogger('mdt_collector')
logger.setLevel(logging.DEBUG)

# InfluxDB configuration
INFLUXDB_URL = os.getenv('INFLUXDB_URL', 'http://localhost:8086')
INFLUXDB_DATABASE = os.getenv('INFLUXDB_DATABASE', 'networkops')
INFLUXDB_ENABLED = os.getenv('INFLUXDB_ENABLED', 'false').lower() == 'true'

# Try to import InfluxDB client
try:
    from influxdb import InfluxDBClient
    INFLUXDB_AVAILABLE = True
except ImportError:
    INFLUXDB_AVAILABLE = False
    logger.info("InfluxDB client not installed. Long-term storage disabled.")

# Add parent directory and proto directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'proto'))

try:
    import grpc
    from google.protobuf import descriptor_pb2
    GRPC_AVAILABLE = True
except ImportError:
    GRPC_AVAILABLE = False
    print("Warning: grpcio not installed. MDT collector disabled.")

# Import compiled proto definitions
try:
    from proto import telemetry_pb2
    from proto import mdt_grpc_dialout_pb2
    PROTO_AVAILABLE = True
except ImportError:
    PROTO_AVAILABLE = False
    print("Warning: Proto files not compiled. Run: cd proto && python -m grpc_tools.protoc -I. --python_out=. telemetry.proto")

try:
    from config.devices import DEVICE_HOSTS
    # Build IP→name map from shared config (invert DEVICE_HOSTS)
    DEVICE_IP_MAP = {ip: name for name, ip in DEVICE_HOSTS.items()}
except ImportError:
    # Fallback if config not available (isolated lab network)
    DEVICE_IP_MAP = {
        '10.255.255.11': 'R1',
        '10.255.255.12': 'R2',
        '10.255.255.13': 'R3',
        '10.255.255.14': 'R4',
        '10.255.255.21': 'Switch-R1',
        '10.255.255.22': 'Switch-R2',
        '10.255.255.24': 'Switch-R4',
        '10.255.255.110': 'Alpine-1',
    }


def is_data_interface(interface_name: str) -> bool:
    """
    Filter to only data interfaces (Gi1-Gi3, Gi5), exclude management/virtual.

    Data interfaces in this lab:
    - Routers: Gi1, Gi2, Gi3, Gi5 (data plane) - exclude Gi4 (management)
    - Switches: Gi1/0/x uplinks

    Excluded:
    - Loopback, Tunnel, Vlan, Null, NVE, BDI interfaces
    - GigabitEthernet4 (management interface)
    """
    if not interface_name:
        return False

    name = interface_name.lower()

    # Exclude virtual interfaces
    if any(x in name for x in ['loopback', 'tunnel', 'vlan', 'null', 'nve', 'bdi']):
        return False

    # For GigabitEthernet (routers), only allow Gi1-Gi3, Gi5
    if 'gigabitethernet' in name:
        import re
        # Match simple interface numbers (e.g., GigabitEthernet1, GigabitEthernet4)
        match = re.search(r'gigabitethernet(\d+)$', name)
        if match:
            intf_num = int(match.group(1))
            # Allow Gi1, Gi2, Gi3, Gi5 - exclude Gi4 (management)
            return intf_num in [1, 2, 3, 5]

        # Allow switch uplinks like Gi1/0/1
        if re.search(r'gigabitethernet\d+/\d+/\d+', name):
            return True

    return False


# Cisco telemetry uses a simple format for kvGPB encoding
# We'll decode the key-value pairs from the protobuf messages


class InfluxDBWriter:
    """Writes telemetry data to InfluxDB for long-term storage"""

    def __init__(self):
        self.client = None
        self._connected = False
        self._write_queue = []
        self._batch_size = 100
        self._last_flush = time.time()
        self._flush_interval = 10  # seconds
        self._lock = threading.Lock()

        if INFLUXDB_ENABLED and INFLUXDB_AVAILABLE:
            self._connect()

    def _connect(self):
        """Connect to InfluxDB"""
        try:
            # Parse URL to get host and port
            from urllib.parse import urlparse
            parsed = urlparse(INFLUXDB_URL)
            host = parsed.hostname or 'localhost'
            port = parsed.port or 8086

            self.client = InfluxDBClient(
                host=host,
                port=port,
                database=INFLUXDB_DATABASE
            )
            # Test connection
            self.client.ping()
            self._connected = True
            logger.info(f"Connected to InfluxDB at {INFLUXDB_URL}/{INFLUXDB_DATABASE}")
        except Exception as e:
            logger.error(f"Failed to connect to InfluxDB: {e}")
            self._connected = False

    def write_interface_stats(self, device: str, interface: str, stats: dict):
        """Queue interface statistics for writing"""
        if not self._connected:
            return

        point = {
            'measurement': 'interface_stats',
            'tags': {
                'device': device,
                'interface': interface.replace('/', '_')
            },
            'fields': {
                'in_octets': int(stats.get('in_octets', 0)),
                'out_octets': int(stats.get('out_octets', 0)),
                'in_packets': int(stats.get('in_packets', 0)),
                'out_packets': int(stats.get('out_packets', 0))
            }
        }
        self._queue_point(point)

    def write_cpu_stats(self, device: str, cpu_percent: float):
        """Queue CPU statistics for writing"""
        if not self._connected:
            return

        point = {
            'measurement': 'cpu_stats',
            'tags': {
                'device': device
            },
            'fields': {
                'five_seconds': float(cpu_percent)
            }
        }
        self._queue_point(point)

    def write_memory_stats(self, device: str, used: int, free: int, percent_used: float):
        """Queue memory statistics for writing"""
        if not self._connected:
            return

        point = {
            'measurement': 'memory_stats',
            'tags': {
                'device': device
            },
            'fields': {
                'used': int(used),
                'free': int(free),
                'total': int(used + free),
                'percent_used': float(percent_used)
            }
        }
        self._queue_point(point)

    def write_state_change(self, device: str, interface: str, new_state: str, old_state: str):
        """Queue interface state change event for writing"""
        if not self._connected:
            return

        point = {
            'measurement': 'interface_state_changes',
            'tags': {
                'device': device,
                'interface': interface.replace('/', '_'),
                'new_state': new_state,
                'old_state': old_state
            },
            'fields': {
                'state_value': 1 if new_state == 'up' else 0,
                'event': f"{old_state}_to_{new_state}"
            }
        }
        self._queue_point(point)

    def _queue_point(self, point: dict):
        """Add point to write queue and flush if needed"""
        with self._lock:
            self._write_queue.append(point)

            # Flush if batch size reached or interval elapsed
            if (len(self._write_queue) >= self._batch_size or
                time.time() - self._last_flush >= self._flush_interval):
                self._flush()

    def _flush(self):
        """Write queued points to InfluxDB"""
        if not self._write_queue or not self._connected:
            return

        points = self._write_queue.copy()
        self._write_queue.clear()
        self._last_flush = time.time()

        try:
            self.client.write_points(points)
            logger.debug(f"Wrote {len(points)} points to InfluxDB")
        except Exception as e:
            logger.error(f"Failed to write to InfluxDB: {e}")
            # Re-queue points on failure (up to a limit)
            if len(self._write_queue) < 1000:
                self._write_queue.extend(points)

    def close(self):
        """Flush remaining data and close connection"""
        with self._lock:
            self._flush()
        if self.client:
            self.client.close()


# Global InfluxDB writer instance
influx_writer = InfluxDBWriter()

# Import Redis telemetry store for cross-process data sharing
# Try both import paths: dashboard.telemetry_store (from project root) and
# telemetry_store (from within dashboard directory)
try:
    from dashboard.telemetry_store import get_telemetry_store, RedisTelemetryStore
    REDIS_STORE_AVAILABLE = True
except ImportError:
    REDIS_STORE_AVAILABLE = False
    logger.info("Redis telemetry store not available, using in-memory only")


class TelemetryData:
    """Thread-safe storage for telemetry data.

    Supports optional Redis backing store for cross-process data sharing.
    When Redis is available, data is written to both local memory (for fast access)
    and Redis (for sharing with other processes like the dashboard API).
    """

    def __init__(self, use_redis: bool = True):
        self._lock = threading.Lock()
        self._interface_stats = defaultdict(dict)  # {device: {interface: stats}}
        self._cpu_stats = {}  # {device: cpu_percent}
        self._memory_stats = {}  # {device: {used, free, total}}
        self._interface_states = defaultdict(dict)  # {device: {interface: state}}
        self._state_change_history = []  # List of recent state changes (max 100)
        self._last_update = {}  # {device: timestamp}
        self._subscribers = []  # WebSocket callbacks

        # Initialize Redis store for cross-process sharing
        self._redis_store = None
        if use_redis and REDIS_STORE_AVAILABLE:
            try:
                self._redis_store = get_telemetry_store()
                if self._redis_store.is_redis_available:
                    logger.info("TelemetryData: Redis backing store enabled")
                else:
                    logger.info("TelemetryData: Redis unavailable, using in-memory only")
                    self._redis_store = None
            except Exception as e:
                logger.warning(f"TelemetryData: Failed to init Redis store: {e}")
                self._redis_store = None

    def update_interface_stats(self, device: str, interface: str, stats: dict):
        """Update interface statistics for a device"""
        with self._lock:
            self._interface_stats[device][interface] = {
                **stats,
                'timestamp': isonow()
            }
            self._last_update[device] = isonow()
        self._notify_subscribers('interface', device, interface, stats)
        # Write to InfluxDB for long-term storage
        influx_writer.write_interface_stats(device, interface, stats)
        # Write to Redis for cross-process sharing
        if self._redis_store:
            self._redis_store.update_interface_stats(device, interface, stats)

    def update_cpu_stats(self, device: str, cpu_percent: float):
        """Update CPU utilization for a device"""
        with self._lock:
            self._cpu_stats[device] = {
                'five_seconds': cpu_percent,
                'timestamp': isonow()
            }
            self._last_update[device] = isonow()
        self._notify_subscribers('cpu', device, None, {'cpu_percent': cpu_percent})
        # Write to InfluxDB for long-term storage
        influx_writer.write_cpu_stats(device, cpu_percent)
        # Write to Redis for cross-process sharing
        if self._redis_store:
            self._redis_store.update_cpu_stats(device, cpu_percent)

    def update_memory_stats(self, device: str, used: int, free: int):
        """Update memory statistics for a device"""
        # Ensure values are positive
        used = max(0, used)
        free = max(0, free)
        total = used + free

        # Only update if we have meaningful data
        if total <= 0:
            return

        percent_used = round((used / total) * 100, 1)

        with self._lock:
            self._memory_stats[device] = {
                'used': used,
                'free': free,
                'total': total,
                'percent_used': percent_used,
                'timestamp': isonow()
            }
            self._last_update[device] = isonow()
        self._notify_subscribers('memory', device, None, self._memory_stats[device])
        # Write to InfluxDB for long-term storage
        influx_writer.write_memory_stats(device, used, free, percent_used)
        # Write to Redis for cross-process sharing
        if self._redis_store:
            self._redis_store.update_memory_stats(device, used, free)

    def update_interface_state(self, device: str, interface: str, new_state: str):
        """
        Update interface operational state (from on-change subscription).
        Tracks state changes and logs events.

        States: if-oper-state-ready (up), if-oper-state-no-pass (down), etc.
        """
        timestamp = isonow()

        # Normalize state to simple up/down
        state_up = 'ready' in new_state.lower() or new_state.lower() == 'up'
        simple_state = 'up' if state_up else 'down'

        event = None
        with self._lock:
            # Get previous state
            prev_state = self._interface_states[device].get(interface, {}).get('state')

            # Update current state
            self._interface_states[device][interface] = {
                'state': simple_state,
                'raw_state': new_state,
                'timestamp': timestamp
            }
            self._last_update[device] = timestamp

            # Check if state changed
            if prev_state is not None and prev_state != simple_state:
                # State changed! Log and record the event
                event = {
                    'device': device,
                    'interface': interface,
                    'old_state': prev_state,
                    'new_state': simple_state,
                    'raw_state': new_state,
                    'timestamp': timestamp
                }

                # Add to history (keep last 100)
                self._state_change_history.append(event)
                if len(self._state_change_history) > 100:
                    self._state_change_history.pop(0)

        # Notify subscribers OUTSIDE the lock to prevent deadlock
        if event:
            # Log the event prominently
            direction = '🔴 DOWN' if simple_state == 'down' else '🟢 UP'
            logger.warning(f"[STATE CHANGE] {device} {interface}: {prev_state} → {simple_state} {direction}")
            print(f"\n{'='*60}")
            print(f"⚡ INTERFACE STATE CHANGE DETECTED")
            print(f"   Device:    {device}")
            print(f"   Interface: {interface}")
            print(f"   Change:    {prev_state.upper()} → {simple_state.upper()} {direction}")
            print(f"   Time:      {timestamp}")
            print(f"{'='*60}\n", flush=True)

            # Notify subscribers (outside lock to prevent deadlock)
            self._notify_subscribers('state_change', device, interface, event)

            # Write to InfluxDB
            influx_writer.write_state_change(device, interface, simple_state, prev_state)

        # Write to Redis for cross-process sharing (also detects state changes)
        if self._redis_store:
            self._redis_store.update_interface_state(device, interface, new_state)

        return event

    def get_interface_states(self) -> dict:
        """Get current interface states for all devices"""
        with self._lock:
            return {device: dict(states) for device, states in self._interface_states.items()}

    def get_state_change_history(self, limit: int = 50) -> list:
        """Get recent state change events"""
        with self._lock:
            return list(self._state_change_history[-limit:])

    def get_all_stats(self) -> dict:
        """Get all telemetry data.

        Prefers Redis data if local data is empty (cross-process scenario).
        """
        # If Redis is available and we have no local data, read from Redis
        if self._redis_store and not self._interface_stats and not self._cpu_stats:
            return self._redis_store.get_all_stats()

        with self._lock:
            return {
                'interfaces': dict(self._interface_stats),
                'cpu': dict(self._cpu_stats),
                'memory': dict(self._memory_stats),
                'interface_states': {d: dict(s) for d, s in self._interface_states.items()},
                'state_changes': list(self._state_change_history[-10:]),  # Last 10 changes
                'last_update': dict(self._last_update)
            }

    def get_interface_stats(self) -> dict:
        """Get interface statistics for all devices"""
        # Prefer Redis if local is empty
        if self._redis_store and not self._interface_stats:
            return self._redis_store.get_interface_stats()
        with self._lock:
            return dict(self._interface_stats)

    def get_cpu_stats(self) -> dict:
        """Get CPU statistics for all devices"""
        # Prefer Redis if local is empty
        if self._redis_store and not self._cpu_stats:
            return self._redis_store.get_cpu_stats()
        with self._lock:
            return dict(self._cpu_stats)

    def get_memory_stats(self) -> dict:
        """Get memory statistics for all devices"""
        # Prefer Redis if local is empty
        if self._redis_store and not self._memory_stats:
            return self._redis_store.get_memory_stats()
        with self._lock:
            return dict(self._memory_stats)

    def get_device_stats(self, device: str) -> dict:
        """Get telemetry data for a specific device"""
        # Prefer Redis if local is empty
        if self._redis_store and not self._interface_stats:
            return self._redis_store.get_device_stats(device)
        with self._lock:
            return {
                'interfaces': dict(self._interface_stats.get(device, {})),
                'cpu': self._cpu_stats.get(device),
                'memory': self._memory_stats.get(device),
                'last_update': self._last_update.get(device)
            }

    def subscribe(self, callback):
        """Subscribe to telemetry updates"""
        self._subscribers.append(callback)

    def unsubscribe(self, callback):
        """Unsubscribe from telemetry updates"""
        if callback in self._subscribers:
            self._subscribers.remove(callback)

    def _notify_subscribers(self, data_type: str, device: str, interface: str, data: dict):
        """Notify all subscribers of new data"""
        message = {
            'type': data_type,
            'device': device,
            'interface': interface,
            'data': data,
            'timestamp': isonow()
        }
        for callback in self._subscribers:
            try:
                callback(message)
            except Exception as e:
                print(f"Error notifying subscriber: {e}")


# Global telemetry data store
telemetry_data = TelemetryData()


def parse_kvgpb_message(data: bytes, source_ip: str) -> list:
    """
    Parse Cisco kvGPB (key-value Google Protocol Buffer) telemetry message.
    Returns list of (path, key, value) tuples.
    """
    # This is a simplified parser - full implementation would use proper protobuf
    # For now, we'll extract what we can from the binary data
    results = []

    try:
        # The kvGPB format has fields encoded as:
        # - Field number + wire type (varint)
        # - Value (depends on wire type)

        # Look for common patterns in the data
        text = data.decode('utf-8', errors='ignore')

        # Extract interface names (GigabitEthernet patterns)
        import re
        intf_matches = re.findall(r'(GigabitEthernet\d+(?:/\d+)*)', text)

        # Extract numeric values that might be counters
        num_matches = re.findall(r'\b(\d{6,})\b', text)

        if intf_matches:
            results.append(('interface', intf_matches[0], {'found': True}))

    except Exception as e:
        pass

    return results


class TelemetryServicer:
    """gRPC servicer for Cisco MDT"""

    def __init__(self, data_store: TelemetryData):
        self.data_store = data_store
        self.message_count = 0

    def MdtDialout(self, request_iterator, context):
        """Handle streaming telemetry from devices (dial-out mode)"""
        peer = context.peer()
        print(f"MDT connection from: {peer}")

        # Extract IP from peer string (e.g., "ipv4:203.0.113.202:12345")
        source_ip = None
        if peer:
            parts = peer.split(':')
            if len(parts) >= 2:
                source_ip = parts[1]

        device_name = DEVICE_IP_MAP.get(source_ip, source_ip or 'unknown')

        try:
            for request in request_iterator:
                self.message_count += 1

                # Process the telemetry message
                # The actual format depends on the subscription encoding
                # For kvGPB, we need to decode the protobuf fields

                try:
                    # Get raw data from request
                    if hasattr(request, 'data'):
                        raw_data = request.data
                    elif hasattr(request, 'SerializeToString'):
                        raw_data = request.SerializeToString()
                    else:
                        raw_data = bytes(request)

                    # Try to extract useful information
                    self._process_telemetry(device_name, raw_data)

                except Exception as e:
                    print(f"Error processing message from {device_name}: {e}")

        except Exception as e:
            print(f"Stream error from {device_name}: {e}")

        # Return empty response
        return iter([])

    def _process_telemetry(self, device: str, data: bytes):
        """Process raw telemetry data using proper protobuf parsing"""
        if not PROTO_AVAILABLE:
            return self._process_telemetry_fallback(device, data)

        try:
            # Parse the MdtDialoutArgs wrapper
            dialout_msg = mdt_grpc_dialout_pb2.MdtDialoutArgs()
            dialout_msg.ParseFromString(data)

            # The telemetry data is in the 'data' field
            if dialout_msg.data:
                telemetry_msg = telemetry_pb2.Telemetry()
                telemetry_msg.ParseFromString(dialout_msg.data)
                self._process_telemetry_message(device, telemetry_msg)
            else:
                # Try parsing as raw Telemetry message
                telemetry_msg = telemetry_pb2.Telemetry()
                telemetry_msg.ParseFromString(data)
                self._process_telemetry_message(device, telemetry_msg)

        except Exception as e:
            # Debug: log which devices fail proto parsing
            logger.warning(f"Proto parse failed for {device}: {str(e)[:100]}")
            # Fall back to heuristic parsing
            self._process_telemetry_fallback(device, data)

    def _process_telemetry_message(self, device: str, msg):
        """Process a parsed Telemetry protobuf message"""
        # Use node_id_str from message if available (more reliable than source IP with NAT)
        if msg.node_id_str:
            device = msg.node_id_str

        encoding_path = msg.encoding_path

        # Debug: track successful parsing by device (every 100 messages)
        if self.message_count % 100 == 0:
            logger.info(f"Msg #{self.message_count} from {device}: {encoding_path[:60] if encoding_path else 'no-path'}")

        # Process kvGPB data - collect all fields into a flat dict
        all_data = {}
        for field in msg.data_gpbkv:
            self._collect_field_values(field, all_data)

        # Now process based on encoding path
        # IMPORTANT: Check memory BEFORE statistics (memory paths contain 'statistics')
        if 'memory' in encoding_path.lower():
            # Filter to only use the main "Processor" memory pool
            # Skip small pools like "reserve Processor", "lsmpi_io"
            pool_name = all_data.get('name', '')
            if pool_name != 'Processor':
                return

            # Cisco-IOS-XE-memory-oper uses various field names depending on YANG model version
            used = (all_data.get('used-memory', 0) or
                    all_data.get('memory-used', 0) or
                    all_data.get('used-number-of-bytes', 0) or
                    all_data.get('used_memory', 0) or
                    all_data.get('used', 0))
            free = (all_data.get('free-memory', 0) or
                    all_data.get('memory-free', 0) or
                    all_data.get('free-number-of-bytes', 0) or
                    all_data.get('free_memory', 0) or
                    all_data.get('free', 0))

            if used or free:
                logger.debug(f"Memory stats for {device} ({pool_name}): used={used/1024/1024:.1f}MB, free={free/1024/1024:.1f}MB")
                self.data_store.update_memory_stats(device, used, free)

        elif 'cpu' in encoding_path.lower():
            cpu_val = all_data.get('five-seconds', all_data.get('one-minute', 0))
            if cpu_val:
                self.data_store.update_cpu_stats(device, float(cpu_val))

        elif 'interface' in encoding_path.lower():
            interface_name = all_data.get('name', '')

            # Check if this is an on-change message with oper-status (Sub 103)
            # On-change sends path "interfaces/interface" with oper-status in data
            oper_status = all_data.get('oper-status', '')
            if interface_name and oper_status:
                self.data_store.update_interface_state(device, interface_name, oper_status)

            # Also handle statistics if present (Sub 100 - periodic stats)
            if interface_name and is_data_interface(interface_name):
                if 'statistics' in encoding_path.lower() or 'in-octets' in all_data or 'in-octets-64' in all_data:
                    stats = {
                        'in_octets': all_data.get('in-octets', all_data.get('in-octets-64', 0)),
                        'out_octets': all_data.get('out-octets', all_data.get('out-octets-64', 0)),
                        'in_packets': all_data.get('in-unicast-pkts', all_data.get('in-pkts', 0)),
                        'out_packets': all_data.get('out-unicast-pkts', all_data.get('out-pkts', 0)),
                    }
                    self.data_store.update_interface_stats(device, interface_name, stats)

    def _collect_field_values(self, field, data: dict):
        """Recursively collect all field values into a flat dictionary"""
        name = field.name

        # Extract the value
        value = None
        if field.HasField('uint64_value'):
            value = field.uint64_value
        elif field.HasField('uint32_value'):
            value = field.uint32_value
        elif field.HasField('sint64_value'):
            value = field.sint64_value
        elif field.HasField('sint32_value'):
            value = field.sint32_value
        elif field.HasField('double_value'):
            value = field.double_value
        elif field.HasField('float_value'):
            value = field.float_value
        elif field.HasField('string_value'):
            value = field.string_value
        elif field.HasField('bool_value'):
            value = field.bool_value

        if name and value is not None:
            data[name] = value

        # Process nested fields
        for child in field.fields:
            self._collect_field_values(child, data)

    def _process_telemetry_field(self, device: str, path: str, field, parent_data: dict):
        """Recursively process TelemetryField and extract values"""
        name = field.name
        value = None

        # Debug: show field names
        if name:
            print(f"  [Field] {name}", end="")

        # Extract the value based on which field is set
        if field.HasField('uint64_value'):
            value = field.uint64_value
            print(f" = {value} (uint64)") if name else None
        elif field.HasField('uint32_value'):
            value = field.uint32_value
        elif field.HasField('sint64_value'):
            value = field.sint64_value
        elif field.HasField('sint32_value'):
            value = field.sint32_value
        elif field.HasField('double_value'):
            value = field.double_value
        elif field.HasField('float_value'):
            value = field.float_value
        elif field.HasField('string_value'):
            value = field.string_value
        elif field.HasField('bool_value'):
            value = field.bool_value

        # Store in parent data
        if name and value is not None:
            parent_data[name] = value

        # Process nested fields
        child_data = {}
        for child in field.fields:
            self._process_telemetry_field(device, path, child, child_data)

        # Merge child data
        if child_data:
            if name:
                parent_data[name] = child_data
            else:
                parent_data.update(child_data)

        # Update data store based on path type
        if 'interface' in path.lower() or 'statistics' in path.lower():
            interface = parent_data.get('name') or child_data.get('name')
            # Filter to only data interfaces
            if interface and is_data_interface(interface):
                stats = {
                    'in_octets': child_data.get('in-octets', child_data.get('in-octets-64', child_data.get('rx-octets', 0))),
                    'out_octets': child_data.get('out-octets', child_data.get('out-octets-64', child_data.get('tx-octets', 0))),
                    'in_packets': child_data.get('in-unicast-pkts', child_data.get('in-pkts', child_data.get('rx-pkts', 0))),
                    'out_packets': child_data.get('out-unicast-pkts', child_data.get('out-pkts', child_data.get('tx-pkts', 0))),
                }
                if any(v > 0 for v in stats.values()):
                    self.data_store.update_interface_stats(device, interface, stats)

        elif 'cpu' in path.lower():
            cpu_val = child_data.get('five-seconds', child_data.get('one-minute', 0))
            if cpu_val:
                self.data_store.update_cpu_stats(device, float(cpu_val))

        elif 'memory' in path.lower():
            # Comprehensive field name fallbacks for memory
            used = (child_data.get('used-memory', 0) or
                    child_data.get('memory-used', 0) or
                    child_data.get('used-number-of-bytes', 0) or
                    child_data.get('used', 0))
            free = (child_data.get('free-memory', 0) or
                    child_data.get('memory-free', 0) or
                    child_data.get('free-number-of-bytes', 0) or
                    child_data.get('free', 0))
            if used or free:
                self.data_store.update_memory_stats(device, used, free)

    def _process_telemetry_fallback(self, device: str, data: bytes):
        """Fallback heuristic parsing when proto parsing fails"""
        import re
        text = data.decode('utf-8', errors='ignore')

        # Extract interface name - only GigabitEthernet (data interfaces filtered below)
        intf_match = re.search(r'(GigabitEthernet\d+(?:/\d+)*)', text)
        if intf_match:
            interface = intf_match.group(1)
            # Filter to only data interfaces (exclude Gi4, etc.)
            if is_data_interface(interface):
                # Just register the interface with zero counters
                self.data_store.update_interface_stats(device, interface, {
                    'in_octets': 0, 'out_octets': 0, 'in_packets': 0, 'out_packets': 0
                })


class MDTCollector:
    """MDT gRPC Collector Server"""

    def __init__(self, port: int = 57000):
        self.port = port
        self.server = None
        self._running = False
        self._thread = None
        self.data = telemetry_data
        self.servicer = TelemetryServicer(self.data)

    def start(self):
        """Start the gRPC server"""
        if not GRPC_AVAILABLE:
            print("gRPC not available - MDT collector disabled")
            return False

        if self._running:
            return True

        try:
            self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=50))

            # Add generic service handler since we don't have the proto file
            # The device will connect and stream data

            # For Cisco MDT, the service is typically:
            # service gRPCMdtDialout {
            #   rpc MdtDialout(stream MdtDialoutArgs) returns (stream MdtDialoutArgs);
            # }

            # We'll use a generic handler
            self.server.add_generic_rpc_handlers([GenericHandler(self.servicer)])

            self.server.add_insecure_port(f'[::]:{self.port}')
            self.server.start()
            self._running = True

            print(f"MDT Collector started on port {self.port}")
            return True

        except Exception as e:
            print(f"Failed to start MDT collector: {e}")
            return False

    def stop(self):
        """Stop the gRPC server"""
        if self.server:
            self.server.stop(grace=5)
            self._running = False
            print("MDT Collector stopped")

    def get_stats(self) -> dict:
        """Get collector statistics and update Redis status"""
        stats = {
            'running': self._running,
            'port': self.port,
            'message_count': self.servicer.message_count,
            'connected_devices': list(self.data._last_update.keys())
        }
        # Update Redis with collector status for cross-process visibility
        if self.data._redis_store:
            self.data._redis_store.set_collector_status(
                running=self._running,
                port=self.port,
                message_count=self.servicer.message_count,
                connected_devices=stats['connected_devices']
            )
        return stats


# Only define GenericHandler when grpc is available
if GRPC_AVAILABLE:
    class GenericHandler(grpc.GenericRpcHandler):
        """Generic gRPC handler for MDT streams"""

        def __init__(self, servicer):
            self.servicer = servicer

        def service(self, handler_call_details):
            """Route incoming calls to our servicer"""
            # Log incoming RPC details
            print(f"[MDT] gRPC method called: {handler_call_details.method}", flush=True)
            # Accept any method name - Cisco uses MdtDialout
            # MDT dial-out is bidirectional streaming (stream -> stream)
            return grpc.stream_stream_rpc_method_handler(
                self._handle_stream,
                request_deserializer=lambda x: x,
                response_serializer=lambda x: x,
            )

        def _handle_stream(self, request_iterator, context):
            """Handle incoming telemetry stream (bidirectional)"""
            peer = context.peer()

            # Extract device IP
            source_ip = None
            if peer:
                parts = peer.split(':')
                if len(parts) >= 2:
                    source_ip = parts[1]

            device_name = DEVICE_IP_MAP.get(source_ip, source_ip or 'unknown')
            logger.info(f"MDT stream connected: peer={peer}, ip={source_ip}, device={device_name}")

            # Process each message in the stream
            msg_count = 0
            try:
                for request in request_iterator:
                    self.servicer.message_count += 1
                    msg_count += 1
                    if msg_count == 1:
                        logger.info(f"First message from {device_name}")
                    self.servicer._process_telemetry(device_name, request)
            except Exception as e:
                logger.error(f"MDT stream error from {device_name} after {msg_count} msgs: {e}")

            # Bidirectional stream - yield empty responses
            return
            yield  # Makes this a generator


# Singleton collector instance
_collector = None

def get_mdt_collector(port: int = 57000) -> MDTCollector:
    """Get or create the MDT collector singleton"""
    global _collector
    if _collector is None:
        _collector = MDTCollector(port=port)
    return _collector


if __name__ == '__main__':
    # Test the collector
    collector = get_mdt_collector(57000)
    collector.start()

    try:
        while True:
            time.sleep(5)
            stats = collector.data.get_all_stats()
            print(f"Stats: {stats}")
    except KeyboardInterrupt:
        collector.stop()
