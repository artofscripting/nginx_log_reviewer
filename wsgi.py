#!/usr/bin/env python3
"""
WSGI entry point for NGINX Log Analyzer
Production deployment with Gunicorn
"""

import os
import sys

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(__file__))

from app import app

# Configure for production
app.config.update(
    DEBUG=False,
    TESTING=False,
    ENV='production'
)

# WSGI application callable
application = app

if __name__ == "__main__":
    # This is for development only
    app.run(host='0.0.0.0', port=5006, debug=False)