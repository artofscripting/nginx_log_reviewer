# 🚀 NGINX Access Log Analyzer

A comprehensive Python Flask web application for analyzing NGINX access logs with advanced analytics, real-time monitoring, and professional PDF reporting capabilities.

![Python](https://img.shields.io/badge/python-v3.8+-blue.svg)
![Flask](https://img.shields.io/badge/flask-v3.0+-green.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## 📋 Table of Contents

- [Features](#-features)
- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Usage](#-usage)
- [PDF Reports](#-pdf-reports)
- [API Endpoints](#-api-endpoints)
- [Configuration](#-configuration)
- [Contributing](#-contributing)
- [License](#-license)

## ✨ Features

### 📊 **Analytics Dashboard**
- **Real-time traffic monitoring** with interactive charts
- **Geographic IP analysis** and visualization
- **User agent detection** and browser analytics
- **HTTP status code distribution** with detailed insights
- **Traffic patterns** and peak hour analysis

### 🛡️ **Security Intelligence**
- **Advanced threat detection** with risk scoring
- **Attack pattern analysis** (SQL injection, XSS, etc.)
- **Suspicious IP identification** and tracking
- **Bot detection** and traffic classification
- **Security alerts** with actionable recommendations

### ⚡ **Performance Monitoring**
- **Response time analysis** and optimization insights
- **Bandwidth utilization** tracking
- **Error rate monitoring** with trend analysis
- **Peak traffic handling** assessment
- **Resource utilization** metrics

### 📈 **Business Intelligence**
- **User engagement** analytics
- **Content performance** metrics
- **Device and browser trends**
- **Geographic distribution** insights
- **Conversion tracking** and user behavior

### 📋 **Professional PDF Reports**
- **Executive Summary** reports with KPIs
- **Security Assessment** reports with threat analysis
- **Comprehensive Analytics** reports with all metrics
- **Multi-page professional formatting**
- **Color-coded risk indicators**

### 🔄 **Real-time Features**
- **Live traffic monitoring** with anomaly detection
- **Predictive analytics** with trend forecasting
- **Real-time alerts** for suspicious activity
- **Dynamic dashboard** with auto-refresh
- **Interactive charts** with drill-down capabilities

## 🚀 Quick Start

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/nginx-log-analyzer.git
   cd nginx-log-analyzer
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements-simple.txt
   ```

3. **Run the application**:
   ```bash
   python app.py
   ```

4. **Open your browser**: http://localhost:5006

5. **Load your logs** and start analyzing!

## 🛠️ Installation

### Prerequisites

- Python 3.8 or higher
- NGINX access logs in Combined Log Format
- Modern web browser

### Step-by-Step Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/nginx-log-analyzer.git
   cd nginx-log-analyzer
   ```

2. **Create virtual environment** (recommended):
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install basic dependencies**:
   ```bash
   pip install -r requirements-simple.txt
   ```

4. **Install PDF dependencies** (optional but recommended):
   ```bash
   pip install reportlab==4.0.7 matplotlib==3.8.2
   ```

## 📖 Usage

### Loading Logs

1. Place your NGINX access log files in the project directory
2. Open the web interface at http://localhost:5006
3. Use the "Load Logs" button to analyze files from the last 7 days
4. Adjust the time period using the dropdown menu

### Dashboard Features

- **Summary Statistics**: Total requests, unique IPs, error rates
- **Traffic Analysis**: Interactive charts showing traffic patterns
- **Security Monitoring**: Threat detection and suspicious activity alerts
- **Performance Metrics**: Response times and system performance
- **Geographic Data**: World map with IP geolocation

### Exporting Reports

- **Summary PDF**: Executive overview with key metrics
- **Security PDF**: Detailed threat analysis and security assessment
- **Comprehensive PDF**: Complete analytics report with all features

## 📋 PDF Reports

### Available Report Types

1. **📊 Summary Report**
   - Executive summary with KPIs
   - Top IP addresses with rankings
   - HTTP status code distribution
   - Professional formatting with tables

2. **🛡️ Security Report**
   - Comprehensive threat intelligence
   - High/Medium/Low risk categorization
   - Attack pattern analysis
   - Security recommendations

3. **🚀 Comprehensive Report**
   - Multi-page professional document
   - All analytics sections included
   - Real-time insights and anomaly detection
   - Business intelligence metrics
   - Actionable recommendations

### Report Features

- **Professional styling** with corporate color scheme
- **Color-coded risk indicators** (🔴 High, 🟡 Medium, 🟢 Low)
- **Interactive tables** with detailed data
- **Executive summaries** with key insights
- **Automatic file naming** with timestamps

## 🔌 API Endpoints

### Core Analytics
- `GET /api/summary` - Summary statistics
- `GET /api/traffic_over_time` - Traffic patterns
- `GET /api/status_distribution` - HTTP status codes
- `GET /api/geographic` - Geographic data

### Advanced Analytics
- `GET /api/advanced_analytics` - Bot detection and advanced metrics
- `GET /api/threat_intelligence` - Security threat analysis
- `GET /api/performance_metrics` - Performance monitoring
- `GET /api/real_time_insights` - Real-time monitoring

### PDF Export
- `GET /api/export/pdf/summary` - Summary PDF report
- `GET /api/export/pdf/security` - Security PDF report
- `GET /api/export/pdf/comprehensive` - Complete PDF report

### Data Loading
- `GET /api/load_logs?days=7` - Load logs from specified days

## ⚙️ Configuration

### Log Format Support

The analyzer supports NGINX Combined Log Format:
```
log_format combined '$remote_addr - $remote_user [$time_local] '
                   '"$request" $status $body_bytes_sent '
                   '"$http_referer" "$http_user_agent"';
```

### Customization Options

- **Time periods**: Adjust analysis timeframe
- **IP filtering**: Focus on specific IP ranges
- **Threat thresholds**: Customize security alert levels
- **Report styling**: Modify PDF appearance

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Flask** - Web framework
- **ReportLab** - PDF generation
- **Plotly.js** - Interactive charts
- **Bootstrap** - Responsive UI
- **User-Agents** - Browser detection

## 📞 Support

If you encounter any issues or have questions:

1. Check the documentation files in this repository
2. Search existing issues on GitHub
3. Create a new issue with detailed information

---

**Built with ❤️ for system administrators and security professionals**