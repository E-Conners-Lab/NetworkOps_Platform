"""
Gunicorn configuration for production deployment.

Usage:
    gunicorn -c gunicorn.conf.py api_server:app

Or with Docker:
    CMD ["gunicorn", "-c", "gunicorn.conf.py", "api_server:app"]
"""

import multiprocessing
import os

# Server socket
bind = os.getenv("GUNICORN_BIND", "0.0.0.0:5001")
backlog = 2048

# Worker processes
# Use gevent workers for WebSocket support with Socket.IO
workers = int(os.getenv("GUNICORN_WORKERS", multiprocessing.cpu_count() * 2 + 1))
worker_class = "geventwebsocket.gunicorn.workers.GeventWebSocketWorker"
worker_connections = 1000
timeout = 120
keepalive = 5

# Graceful restart
graceful_timeout = 30
max_requests = 1000
max_requests_jitter = 50

# Logging
accesslog = "-"  # stdout
errorlog = "-"   # stderr
loglevel = os.getenv("GUNICORN_LOG_LEVEL", "info")
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = "network-dashboard-api"

# Security
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

# Hooks
def on_starting(server):
    """Called just before the master process is initialized."""
    pass

def on_exit(server):
    """Called just before exiting Gunicorn."""
    pass

def worker_int(worker):
    """Called when a worker receives SIGINT or SIGQUIT."""
    pass
