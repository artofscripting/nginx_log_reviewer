@echo off
REM Production startup script for NGINX Log Analyzer (Windows)
REM Run with Gunicorn for production deployment

echo.
echo ================================
echo 🚀 NGINX Log Analyzer - Production Mode
echo ================================

REM Check if virtual environment exists
if not exist ".venv" (
    echo ⚠️  Virtual environment not found. Creating...
    python -m venv .venv
)

REM Activate virtual environment
echo 📦 Activating virtual environment...
call .venv\Scripts\activate.bat

REM Install production dependencies
echo 📥 Installing production dependencies...
pip install -r requirements-production.txt

REM Set production environment variables
set FLASK_ENV=production
set PYTHONPATH=%CD%

echo.
echo ✅ Environment setup complete
echo 🔧 Starting Gunicorn server...
echo 📊 Dashboard will be available at: http://localhost:5006
echo 📈 API endpoints available at: http://localhost:5006/api/...
echo 🛑 Press Ctrl+C to stop the server
echo.

REM Start Gunicorn with configuration
gunicorn --config gunicorn.conf.py wsgi:application

pause