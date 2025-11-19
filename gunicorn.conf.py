#!/usr/bin/env python3
"""
Gunicorn configuration file for NGINX Log Analyzer
Production deployment settings with optimized performance
"""

import multiprocessing
import os

# Server socket
bind = "0.0.0.0:5006"
backlog = 2048

# Worker processes
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "sync"
worker_connections = 1000
timeout = 30
keepalive = 2

# Restart workers after this many requests, to help prevent memory leaks
max_requests = 1000
max_requests_jitter = 50

# Logging
accesslog = "-"  # Log to stdout
errorlog = "-"   # Log to stderr
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = 'nginx_log_analyzer'

# Server mechanics
daemon = False
pidfile = '/tmp/nginx_log_analyzer.pid'
user = None
group = None
tmp_upload_dir = None

# SSL (if needed)
# keyfile = "/path/to/keyfile"
# certfile = "/path/to/certfile"

# Worker timeout and graceful shutdown
graceful_timeout = 30
preload_app = True

# Environment variables
raw_env = [
    'FLASK_ENV=production',
    'PYTHONPATH=/app'
]

# Security
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190