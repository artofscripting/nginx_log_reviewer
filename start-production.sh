#!/bin/bash
"""
Production startup script for NGINX Log Analyzer
Run with Gunicorn for production deployment
"""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 Starting NGINX Log Analyzer - Production Mode${NC}"
echo -e "${BLUE}===============================================${NC}"

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo -e "${YELLOW}⚠️  Virtual environment not found. Creating...${NC}"
    python3 -m venv .venv
fi

# Activate virtual environment
echo -e "${BLUE}📦 Activating virtual environment...${NC}"
source .venv/bin/activate

# Install production dependencies
echo -e "${BLUE}📥 Installing production dependencies...${NC}"
pip install -r requirements-production.txt

# Check if log directory exists and is accessible
echo -e "${BLUE}📁 Checking log directory...${NC}"
LOG_DIR="."
if [ ! -r "$LOG_DIR" ]; then
    echo -e "${RED}❌ Cannot read log directory: $LOG_DIR${NC}"
    exit 1
fi

# Set production environment variables
export FLASK_ENV=production
export PYTHONPATH=$PWD

echo -e "${GREEN}✅ Environment setup complete${NC}"
echo -e "${BLUE}🔧 Starting Gunicorn server...${NC}"
echo -e "${YELLOW}📊 Dashboard will be available at: http://localhost:5006${NC}"
echo -e "${YELLOW}📈 API endpoints available at: http://localhost:5006/api/...${NC}"
echo -e "${YELLOW}🛑 Press Ctrl+C to stop the server${NC}"
echo ""

# Start Gunicorn with configuration
exec gunicorn --config gunicorn.conf.py wsgi:application