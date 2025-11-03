# PDF Export Setup Guide

## Installing PDF Dependencies

To enable PDF export functionality, you need to install additional dependencies:

```bash
# Navigate to your project directory
cd "c:\Users\ArtOf\PycharmProjects\NGINX"

# Activate your virtual environment
.\.venv\Scripts\activate.ps1

# Install PDF dependencies
pip install reportlab==4.0.7 matplotlib==3.8.2
```

## PDF Export Features

Once dependencies are installed, your NGINX Log Analyzer will support:

### 📊 **PDF Report Types**
1. **Summary PDF Report** (`/api/export/pdf/summary`)
   - Executive summary with key metrics
   - Top IP addresses and traffic patterns
   - HTTP status code distribution
   - Traffic overview tables

2. **Security PDF Report** (`/api/export/pdf/security`)
   - Comprehensive threat intelligence
   - High/Medium/Low risk threats
   - Attack pattern analysis
   - Security assessment tables

3. **Comprehensive PDF Report** (`/api/export/pdf/comprehensive`)
   - Complete analytics in one document
   - Executive summary
   - Traffic analysis with real-time insights
   - Security intelligence
   - Performance metrics
   - Multi-page professional report

### 🎯 **Export Buttons Updated**
- Main "Export PDF" button (top navigation)
- "Export Detailed PDF Report" button
- "Export Security PDF Report" button  
- "Export Performance PDF Report" button
- "Export Comprehensive PDF Report" button

### 📋 **Report Features**
- Professional PDF formatting with ReportLab
- Structured tables with color coding
- Executive summaries and key insights
- Automatic file naming with timestamps
- Risk-level color coding (Red/Yellow/Green)
- Multi-page comprehensive reports

## Usage

1. **Install dependencies** using the commands above
2. **Start your application**: `python app.py`
3. **Navigate to** http://localhost:5006
4. **Load your logs** using the dashboard
5. **Click any PDF export button** to download professional reports

## Dependencies Included

- **ReportLab 4.0.7**: Professional PDF generation library
- **Matplotlib 3.8.2**: Chart and graph generation for PDF inclusion
- **Flask**: Web framework (already installed)
- **User-Agents**: Browser detection (already installed)

## Error Handling

If PDF generation is not available, the application will:
- Continue to work normally for analytics
- Show helpful error messages for PDF export attempts
- Gracefully degrade to JSON export if needed

The application is designed to work with or without PDF dependencies installed.