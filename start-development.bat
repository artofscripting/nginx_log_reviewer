@echo off
REM Development startup script for NGINX Log Analyzer (Windows)
REM Run with Flask development server for easier debugging

echo.
echo ================================
echo 🛠️  NGINX Log Analyzer - Development Mode
echo ================================

REM Check if virtual environment exists
if not exist ".venv" (
    echo ⚠️  Virtual environment not found. Creating...
    python -m venv .venv
)

REM Activate virtual environment
echo 📦 Activating virtual environment...
call .venv\Scripts\activate.bat

REM Install development dependencies
echo 📥 Installing dependencies...
pip install -r requirements-production.txt

REM Set development environment variables
set FLASK_ENV=development
set FLASK_DEBUG=True
set PYTHONPATH=%CD%

echo.
echo ✅ Environment setup complete
echo 🔧 Starting Flask development server...
echo 📊 Dashboard will be available at: http://localhost:5006
echo 🛠️  Debug mode enabled for development
echo 🗂️  Source maps and dev tools allowed
echo 🛑 Press Ctrl+C to stop the server
echo.

REM Start Flask development server
python app.py

pause