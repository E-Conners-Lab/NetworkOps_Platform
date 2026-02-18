"""
SIEM Log Forwarding Module

Forwards structured logs to Security Information and Event Management systems.
Supports multiple backends:
- Splunk HTTP Event Collector (HEC)
- Elasticsearch
- Syslog (RFC 5424)
- Generic Webhook (HTTP POST)

Usage:
    from core.siem import get_siem_forwarder

    forwarder = get_siem_forwarder()
    forwarder.send_event({
        "event_type": "authentication",
        "user": "admin",
        "action": "login",
        "status": "success",
        "ip": "192.168.1.100"
    })
"""

import os
import json
import logging
import socket
import ssl
import threading
import queue
from datetime import datetime, timezone
from typing import Optional
from dataclasses import dataclass, field
from abc import ABC, abstractmethod

import requests

logger = logging.getLogger("networkops.siem")


@dataclass
class SIEMConfig:
    """SIEM configuration from environment variables."""

    # General settings
    enabled: bool = False
    backend: str = "splunk"  # splunk, elasticsearch, syslog, webhook
    batch_size: int = 10
    flush_interval: float = 5.0  # seconds

    # Splunk HEC
    splunk_url: str = ""
    splunk_token: str = ""
    splunk_index: str = "networkops"
    splunk_source: str = "networkops-api"
    splunk_sourcetype: str = "_json"
    splunk_verify_ssl: bool = True

    # Elasticsearch
    elasticsearch_url: str = ""
    elasticsearch_index: str = "networkops-logs"
    elasticsearch_username: str = ""
    elasticsearch_password: str = ""
    elasticsearch_api_key: str = ""

    # Syslog
    syslog_host: str = "localhost"
    syslog_port: int = 514
    syslog_protocol: str = "udp"  # udp, tcp, tcp+tls
    syslog_facility: int = 1  # user-level

    # Webhook
    webhook_url: str = ""
    webhook_headers: dict = field(default_factory=dict)
    webhook_method: str = "POST"

    @classmethod
    def from_env(cls) -> "SIEMConfig":
        """Load configuration from environment variables."""
        from config.vault_client import get_siem_credentials
        siem_secrets = get_siem_credentials()

        webhook_headers = {}
        headers_str = os.getenv("SIEM_WEBHOOK_HEADERS", "")
        if headers_str:
            try:
                webhook_headers = json.loads(headers_str)
            except json.JSONDecodeError:
                pass

        return cls(
            enabled=os.getenv("SIEM_ENABLED", "false").lower() == "true",
            backend=os.getenv("SIEM_BACKEND", "splunk").lower(),
            batch_size=int(os.getenv("SIEM_BATCH_SIZE", "10")),
            flush_interval=float(os.getenv("SIEM_FLUSH_INTERVAL", "5.0")),

            # Splunk
            splunk_url=os.getenv("SIEM_SPLUNK_URL", ""),
            splunk_token=siem_secrets["splunk_token"],
            splunk_index=os.getenv("SIEM_SPLUNK_INDEX", "networkops"),
            splunk_source=os.getenv("SIEM_SPLUNK_SOURCE", "networkops-api"),
            splunk_sourcetype=os.getenv("SIEM_SPLUNK_SOURCETYPE", "_json"),
            splunk_verify_ssl=os.getenv("SIEM_SPLUNK_VERIFY_SSL", "true").lower() == "true",

            # Elasticsearch
            elasticsearch_url=os.getenv("SIEM_ELASTICSEARCH_URL", ""),
            elasticsearch_index=os.getenv("SIEM_ELASTICSEARCH_INDEX", "networkops-logs"),
            elasticsearch_username=os.getenv("SIEM_ELASTICSEARCH_USERNAME", ""),
            elasticsearch_password=siem_secrets["elasticsearch_password"],
            elasticsearch_api_key=siem_secrets["elasticsearch_api_key"],

            # Syslog
            syslog_host=os.getenv("SIEM_SYSLOG_HOST", "localhost"),
            syslog_port=int(os.getenv("SIEM_SYSLOG_PORT", "514")),
            syslog_protocol=os.getenv("SIEM_SYSLOG_PROTOCOL", "udp").lower(),
            syslog_facility=int(os.getenv("SIEM_SYSLOG_FACILITY", "1")),

            # Webhook
            webhook_url=os.getenv("SIEM_WEBHOOK_URL", ""),
            webhook_headers=webhook_headers,
            webhook_method=os.getenv("SIEM_WEBHOOK_METHOD", "POST").upper(),
        )


class SIEMBackend(ABC):
    """Abstract base class for SIEM backends."""

    @abstractmethod
    def send_events(self, events: list[dict]) -> bool:
        """Send a batch of events to the SIEM."""
        pass

    @abstractmethod
    def close(self):
        """Clean up resources."""
        pass


class SplunkHECBackend(SIEMBackend):
    """Splunk HTTP Event Collector backend."""

    def __init__(self, config: SIEMConfig):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Splunk {config.splunk_token}",
            "Content-Type": "application/json",
        })

    def send_events(self, events: list[dict]) -> bool:
        """Send events to Splunk HEC."""
        if not self.config.splunk_url or not self.config.splunk_token:
            logger.warning("Splunk HEC not configured")
            return False

        try:
            # Format events for Splunk HEC
            payload = ""
            for event in events:
                hec_event = {
                    "time": event.get("timestamp", datetime.now(timezone.utc).timestamp()),
                    "host": socket.gethostname(),
                    "source": self.config.splunk_source,
                    "sourcetype": self.config.splunk_sourcetype,
                    "index": self.config.splunk_index,
                    "event": event,
                }
                payload += json.dumps(hec_event)

            response = self.session.post(
                f"{self.config.splunk_url}/services/collector/event",
                data=payload,
                verify=self.config.splunk_verify_ssl,
                timeout=10,
            )

            if response.status_code == 200:
                logger.debug(f"Sent {len(events)} events to Splunk")
                return True
            else:
                logger.error(f"Splunk HEC error: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"Failed to send to Splunk: {e}")
            return False

    def close(self):
        self.session.close()


class ElasticsearchBackend(SIEMBackend):
    """Elasticsearch backend."""

    def __init__(self, config: SIEMConfig):
        self.config = config
        self.session = requests.Session()

        # Configure authentication
        if config.elasticsearch_api_key:
            self.session.headers["Authorization"] = f"ApiKey {config.elasticsearch_api_key}"
        elif config.elasticsearch_username and config.elasticsearch_password:
            self.session.auth = (config.elasticsearch_username, config.elasticsearch_password)

        self.session.headers["Content-Type"] = "application/x-ndjson"

    def send_events(self, events: list[dict]) -> bool:
        """Send events to Elasticsearch using bulk API."""
        if not self.config.elasticsearch_url:
            logger.warning("Elasticsearch not configured")
            return False

        try:
            # Format for Elasticsearch bulk API
            bulk_data = ""
            index_name = f"{self.config.elasticsearch_index}-{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"

            for event in events:
                # Add timestamp if not present
                if "@timestamp" not in event:
                    event["@timestamp"] = datetime.now(timezone.utc).isoformat()

                bulk_data += json.dumps({"index": {"_index": index_name}}) + "\n"
                bulk_data += json.dumps(event) + "\n"

            response = self.session.post(
                f"{self.config.elasticsearch_url}/_bulk",
                data=bulk_data,
                timeout=10,
            )

            if response.status_code in (200, 201):
                result = response.json()
                if not result.get("errors"):
                    logger.debug(f"Sent {len(events)} events to Elasticsearch")
                    return True
                else:
                    logger.error(f"Elasticsearch bulk errors: {result}")
                    return False
            else:
                logger.error(f"Elasticsearch error: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"Failed to send to Elasticsearch: {e}")
            return False

    def close(self):
        self.session.close()


class SyslogBackend(SIEMBackend):
    """Syslog backend (RFC 5424)."""

    SEVERITY_MAP = {
        "emergency": 0,
        "alert": 1,
        "critical": 2,
        "error": 3,
        "warning": 4,
        "notice": 5,
        "info": 6,
        "debug": 7,
    }

    def __init__(self, config: SIEMConfig):
        self.config = config
        self.socket = None
        self._connect()

    def _connect(self):
        """Establish syslog connection."""
        try:
            if self.config.syslog_protocol == "udp":
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            elif self.config.syslog_protocol == "tcp":
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.connect((self.config.syslog_host, self.config.syslog_port))
            elif self.config.syslog_protocol == "tcp+tls":
                context = ssl.create_default_context()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket = context.wrap_socket(sock, server_hostname=self.config.syslog_host)
                self.socket.connect((self.config.syslog_host, self.config.syslog_port))
        except Exception as e:
            logger.error(f"Failed to connect to syslog: {e}")
            self.socket = None

    def send_events(self, events: list[dict]) -> bool:
        """Send events via syslog."""
        if not self.socket:
            self._connect()
            if not self.socket:
                return False

        try:
            for event in events:
                # Determine severity
                level = event.get("level", "info").lower()
                severity = self.SEVERITY_MAP.get(level, 6)

                # Calculate PRI (facility * 8 + severity)
                pri = (self.config.syslog_facility * 8) + severity

                # Format RFC 5424 message
                timestamp = event.get("timestamp", datetime.now(timezone.utc).isoformat())
                hostname = socket.gethostname()
                app_name = "networkops"
                proc_id = str(os.getpid())
                msg_id = event.get("event_type", "-")

                # Structured data
                sd = f'[networkops@0 user="{event.get("user", "-")}" action="{event.get("action", "-")}"]'

                # Message
                msg = json.dumps(event)

                syslog_msg = f"<{pri}>1 {timestamp} {hostname} {app_name} {proc_id} {msg_id} {sd} {msg}\n"

                if self.config.syslog_protocol == "udp":
                    self.socket.sendto(
                        syslog_msg.encode("utf-8"),
                        (self.config.syslog_host, self.config.syslog_port)
                    )
                else:
                    self.socket.send(syslog_msg.encode("utf-8"))

            logger.debug(f"Sent {len(events)} events via syslog")
            return True

        except Exception as e:
            logger.error(f"Failed to send syslog: {e}")
            self.socket = None
            return False

    def close(self):
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass


class WebhookBackend(SIEMBackend):
    """Generic webhook backend for custom SIEM integrations."""

    def __init__(self, config: SIEMConfig):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update(config.webhook_headers)
        self.session.headers.setdefault("Content-Type", "application/json")

    def send_events(self, events: list[dict]) -> bool:
        """Send events to webhook endpoint."""
        if not self.config.webhook_url:
            logger.warning("Webhook URL not configured")
            return False

        try:
            payload = {
                "source": "networkops",
                "hostname": socket.gethostname(),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_count": len(events),
                "events": events,
            }

            response = self.session.request(
                method=self.config.webhook_method,
                url=self.config.webhook_url,
                json=payload,
                timeout=10,
            )

            if response.status_code in (200, 201, 202, 204):
                logger.debug(f"Sent {len(events)} events to webhook")
                return True
            else:
                logger.error(f"Webhook error: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"Failed to send to webhook: {e}")
            return False

    def close(self):
        self.session.close()


class SIEMForwarder:
    """
    Asynchronous SIEM log forwarder with batching.

    Events are queued and sent in batches to reduce network overhead.
    A background thread handles the actual sending.
    """

    def __init__(self, config: Optional[SIEMConfig] = None):
        self.config = config or SIEMConfig.from_env()
        self.backend: Optional[SIEMBackend] = None
        self.event_queue: queue.Queue = queue.Queue()
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None

        if self.config.enabled:
            self._init_backend()
            self._start_worker()

    def _init_backend(self):
        """Initialize the appropriate SIEM backend."""
        backend_map = {
            "splunk": SplunkHECBackend,
            "elasticsearch": ElasticsearchBackend,
            "syslog": SyslogBackend,
            "webhook": WebhookBackend,
        }

        backend_class = backend_map.get(self.config.backend)
        if backend_class:
            self.backend = backend_class(self.config)
            logger.info(f"SIEM forwarder initialized: {self.config.backend}")
        else:
            logger.error(f"Unknown SIEM backend: {self.config.backend}")

    def _start_worker(self):
        """Start the background worker thread."""
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker_thread.start()

    def _worker_loop(self):
        """Background worker that batches and sends events."""
        batch = []
        last_flush = datetime.now(timezone.utc)

        while not self._stop_event.is_set():
            try:
                # Get event with timeout
                event = self.event_queue.get(timeout=1.0)
                batch.append(event)
            except queue.Empty:
                pass

            # Flush if batch is full or interval elapsed
            now = datetime.now(timezone.utc)
            elapsed = (now - last_flush).total_seconds()

            if batch and (len(batch) >= self.config.batch_size or elapsed >= self.config.flush_interval):
                self._flush_batch(batch)
                batch = []
                last_flush = now

        # Final flush on shutdown
        if batch:
            self._flush_batch(batch)

    def _flush_batch(self, batch: list[dict]):
        """Send a batch of events to the SIEM."""
        if self.backend and batch:
            try:
                self.backend.send_events(batch)
            except Exception as e:
                logger.error(f"SIEM flush failed: {e}")

    def send_event(self, event: dict):
        """
        Queue an event for sending to SIEM.

        Args:
            event: Dictionary containing event data
        """
        if not self.config.enabled:
            return

        # Add metadata if not present
        if "timestamp" not in event:
            event["timestamp"] = datetime.now(timezone.utc).isoformat()
        if "hostname" not in event:
            event["hostname"] = socket.gethostname()
        if "service" not in event:
            event["service"] = "networkops"

        try:
            self.event_queue.put_nowait(event)
        except queue.Full:
            logger.warning("SIEM event queue full, dropping event")

    def send_security_event(
        self,
        event_type: str,
        user: Optional[str] = None,
        action: str = "",
        status: str = "success",
        details: Optional[dict] = None,
        severity: str = "info",
        ip_address: Optional[str] = None,
    ):
        """
        Send a structured security event.

        Args:
            event_type: Type of event (authentication, authorization, config_change, etc.)
            user: Username associated with event
            action: Specific action taken
            status: success, failure, blocked, etc.
            details: Additional event details
            severity: emergency, alert, critical, error, warning, notice, info, debug
            ip_address: Source IP address
        """
        event = {
            "event_type": event_type,
            "category": "security",
            "user": user or "system",
            "action": action,
            "status": status,
            "severity": severity,
            "ip_address": ip_address,
            "details": details or {},
        }
        self.send_event(event)

    def flush(self):
        """Force flush all queued events."""
        if not self.config.enabled or not self.backend:
            return

        batch = []
        while True:
            try:
                event = self.event_queue.get_nowait()
                batch.append(event)
            except queue.Empty:
                break

        if batch:
            self._flush_batch(batch)

    def close(self):
        """Shut down the forwarder gracefully."""
        if self._worker_thread:
            self._stop_event.set()
            self._worker_thread.join(timeout=5.0)

        self.flush()

        if self.backend:
            self.backend.close()


# Singleton instance
_siem_forwarder: Optional[SIEMForwarder] = None


def get_siem_forwarder() -> SIEMForwarder:
    """Get or create the SIEM forwarder singleton."""
    global _siem_forwarder
    if _siem_forwarder is None:
        _siem_forwarder = SIEMForwarder()
    return _siem_forwarder


def send_security_event(
    event_type: str,
    user: Optional[str] = None,
    action: str = "",
    status: str = "success",
    details: Optional[dict] = None,
    severity: str = "info",
    ip_address: Optional[str] = None,
):
    """Convenience function to send a security event."""
    get_siem_forwarder().send_security_event(
        event_type=event_type,
        user=user,
        action=action,
        status=status,
        details=details,
        severity=severity,
        ip_address=ip_address,
    )
