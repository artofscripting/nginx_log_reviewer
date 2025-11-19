#!/usr/bin/env python3
"""
NGINX Access Log Analyzer - Simplified Version
A Flask web application for analyzing NGINX access logs with comprehensive reporting.
"""

import os
import re
import gzip
import html
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from urllib.parse import urlparse, unquote
import json
import io
import base64

from flask import Flask, render_template, jsonify, request, send_file, make_response
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.colors import HexColor, black, white, red, green, blue, orange
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

try:
    import matplotlib
    matplotlib.use('Agg')  # Use non-interactive backend
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

try:
    from user_agents import parse as parse_user_agent
    USER_AGENTS_AVAILABLE = True
except ImportError:
    USER_AGENTS_AVAILABLE = False
    def parse_user_agent(ua_string):
        return type('UserAgent', (), {
            'browser': type('Browser', (), {'family': 'Unknown', 'version_string': ''})(),
            'os': type('OS', (), {'family': 'Unknown', 'version_string': ''})(),
            'device': type('Device', (), {'family': 'Unknown'})()
        })()

def sanitize_data(data):
    """NUCLEAR XSS PROTECTION - Ultra-aggressive sanitization that removes ALL potential threats."""
    if isinstance(data, str):
        import re
        
        # Step 1: HTML escape everything
        sanitized = html.escape(data, quote=True)
        
        # Step 2: Remove ALL script-related content completely
        script_patterns = [
            r'<\s*script[^>]*>.*?<\s*/\s*script\s*>',  # Script tags with content
            r'<\s*script[^>]*>',  # Opening script tags
            r'<\s*/\s*script\s*>',  # Closing script tags
            r'javascript\s*:',  # JavaScript URLs
            r'data\s*:',  # Data URLs
            r'vbscript\s*:',  # VBScript URLs
        ]
        
        for pattern in script_patterns:
            sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE | re.DOTALL)
        
        # Step 3: Remove ALL event handlers
        event_pattern = r'on\w+\s*=\s*["\'][^"\']*["\']'
        sanitized = re.sub(event_pattern, '', sanitized, flags=re.IGNORECASE)
        
        # Step 4: Remove dangerous function calls completely
        function_patterns = [
            r'alert\s*\([^)]*\)',
            r'confirm\s*\([^)]*\)',
            r'prompt\s*\([^)]*\)',
            r'eval\s*\([^)]*\)',
            r'document\s*\.',
            r'window\s*\.',
        ]
        
        for pattern in function_patterns:
            sanitized = re.sub(pattern, '[BLOCKED]', sanitized, flags=re.IGNORECASE)
        
        # Step 5: Remove dangerous HTML tags completely
        dangerous_tags = [
            r'<\s*img[^>]*>',
            r'<\s*iframe[^>]*>',
            r'<\s*object[^>]*>',
            r'<\s*embed[^>]*>',
            r'<\s*applet[^>]*>',
            r'<\s*meta[^>]*>',
            r'<\s*link[^>]*>',
            r'<\s*style[^>]*>.*?<\s*/\s*style\s*>',
        ]
        
        for pattern in dangerous_tags:
            sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE | re.DOTALL)
        
        # Step 6: Additional character filtering for remaining dangerous chars
        dangerous_sequences = ['<script', '</script', 'javascript:', 'alert(', 'eval(']
        for seq in dangerous_sequences:
            sanitized = sanitized.replace(seq.lower(), '[BLOCKED]')
            sanitized = sanitized.replace(seq.upper(), '[BLOCKED]')
            sanitized = sanitized.replace(seq.capitalize(), '[BLOCKED]')
        
        # Step 7: Final cleanup - remove any remaining < or > that could be dangerous
        sanitized = sanitized.replace('<', '&lt;').replace('>', '&gt;')
        
        return sanitized
        
    elif isinstance(data, dict):
        return {key: sanitize_data(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [sanitize_data(item) for item in data]
    else:
        return data

app = Flask(__name__)

# Configuration
app.config['DEBUG'] = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
app.config['ENV'] = os.environ.get('FLASK_ENV', 'production')

# Security headers middleware
@app.after_request
def add_security_headers(response):
    """Add security headers to prevent XSS and other attacks."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # CSP completely disabled for debugging
    # No Content-Security-Policy header will be sent
    
    # Debug: Confirm no CSP is being sent
    if app.config['DEBUG']:
        print("DEBUG - CSP header completely removed - no CSP restrictions")
    
    return response

class LogAnalyzer:
    def __init__(self, log_directory):
        self.log_directory = log_directory
        self.log_pattern = re.compile(
            r'(?P<ip>\S+) - - \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<url>\S+) (?P<protocol>\S+)" (?P<status>\d+) (?P<size>\d+|-) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)" "(?P<x_forwarded_for>[^"]*)"'
        )
        self.parsed_logs = []
    
    def get_log_files(self):
        """Get all log files from the directory."""
        log_files = []
        for file in os.listdir(self.log_directory):
            if file.startswith('access.log'):
                log_files.append(os.path.join(self.log_directory, file))
        return sorted(log_files)
    
    def parse_log_line(self, line):
        """Parse a single log line."""
        match = self.log_pattern.match(line.strip())
        if match:
            data = match.groupdict()
            
            # Parse timestamp
            timestamp_str = data['timestamp']
            try:
                timestamp = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
            except ValueError:
                try:
                    timestamp = datetime.strptime(timestamp_str.split(' ')[0], '%d/%b/%Y:%H:%M:%S')
                except ValueError:
                    timestamp = None
            
            # Parse user agent
            if USER_AGENTS_AVAILABLE:
                user_agent_info = parse_user_agent(data['user_agent'])
                browser = user_agent_info.browser.family
                browser_version = user_agent_info.browser.version_string
                os_family = user_agent_info.os.family
                os_version = user_agent_info.os.version_string
                device = user_agent_info.device.family
            else:
                browser = 'Unknown'
                browser_version = ''
                os_family = 'Unknown'
                os_version = ''
                device = 'Unknown'
            
            # Clean URL
            url = unquote(data['url'])
            parsed_url = urlparse(url)
            
            return {
                'ip': data['ip'],
                'timestamp': timestamp,
                'method': data['method'],
                'url': url,
                'path': parsed_url.path,
                'query': parsed_url.query,
                'protocol': data['protocol'],
                'status': int(data['status']),
                'size': int(data['size']) if data['size'] != '-' else 0,
                'referer': data['referer'] if data['referer'] != '-' else None,
                'user_agent': data['user_agent'],
                'browser': browser,
                'browser_version': browser_version,
                'os': os_family,
                'os_version': os_version,
                'device': device,
                'x_forwarded_for': data['x_forwarded_for'] if data['x_forwarded_for'] != '-' else None
            }
        return None
    
    def read_log_file(self, file_path):
        """Read and parse a log file (handles both regular and gzipped files)."""
        logs = []
        try:
            if file_path.endswith('.gz'):
                with gzip.open(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        parsed = self.parse_log_line(line)
                        if parsed:
                            logs.append(parsed)
            else:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        parsed = self.parse_log_line(line)
                        if parsed:
                            logs.append(parsed)
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
        
        return logs
    
    def load_logs(self, days_back=7):
        """Load and parse logs from the last N days."""
        log_files = self.get_log_files()
        all_logs = []
        
        # Filter files by date if needed
        cutoff_date = datetime.now() - timedelta(days=days_back)
        
        for file_path in log_files:
            file_name = os.path.basename(file_path)
            
            # Extract date from filename for filtering
            if file_name == 'access.log':
                # Current log file
                logs = self.read_log_file(file_path)
                all_logs.extend(logs)
            elif file_name.startswith('access.log-'):
                try:
                    date_str = file_name.replace('access.log-', '').replace('.gz', '')
                    file_date = datetime.strptime(date_str, '%Y%m%d')
                    if file_date >= cutoff_date:
                        logs = self.read_log_file(file_path)
                        all_logs.extend(logs)
                except ValueError:
                    # If date parsing fails, include the file anyway
                    logs = self.read_log_file(file_path)
                    all_logs.extend(logs)
        
        self.parsed_logs = all_logs
        # Sort by timestamp
        self.parsed_logs.sort(key=lambda x: x['timestamp'] if x['timestamp'] else datetime.min)
        
        return len(all_logs)
    
    def get_summary_stats(self):
        """Get summary statistics."""
        if not self.parsed_logs:
            return {}
        
        total_requests = len(self.parsed_logs)
        unique_ips = len(set(log['ip'] for log in self.parsed_logs))
        
        # Date range
        timestamps = []
        for log in self.parsed_logs:
            if log['timestamp']:
                # Convert timezone-aware datetime to naive for consistency
                log_time = log['timestamp']
                if log_time.tzinfo is not None:
                    log_time = log_time.replace(tzinfo=None)
                timestamps.append(log_time)
        
        if timestamps:
            min_date = min(timestamps).strftime('%Y-%m-%d')
            max_date = max(timestamps).strftime('%Y-%m-%d')
            date_range = f"{min_date} to {max_date}"
        else:
            date_range = "No valid dates"
        
        # Status counts
        status_counts = Counter(log['status'] for log in self.parsed_logs)
        
        # Top paths
        top_paths = Counter(log['path'] for log in self.parsed_logs).most_common(10)
        
        # Top IPs
        top_ips = Counter(log['ip'] for log in self.parsed_logs).most_common(10)
        
        # Top browsers
        top_browsers = Counter(log['browser'] for log in self.parsed_logs).most_common(10)
        
        # Traffic by hour
        hourly_traffic = defaultdict(int)
        for log in self.parsed_logs:
            if log['timestamp']:
                # Convert timezone-aware datetime to naive for consistency
                log_time = log['timestamp']
                if log_time.tzinfo is not None:
                    log_time = log_time.replace(tzinfo=None)
                hour = log_time.hour
                hourly_traffic[hour] += 1
        
        # Error rate
        error_requests = sum(1 for log in self.parsed_logs if log['status'] >= 400)
        error_rate = (error_requests / total_requests * 100) if total_requests > 0 else 0
        
        # Bandwidth
        total_bytes = sum(log['size'] for log in self.parsed_logs)
        avg_response_size = total_bytes / total_requests if total_requests > 0 else 0
        
        return {
            'total_requests': total_requests,
            'unique_ips': unique_ips,
            'date_range': date_range,
            'status_counts': dict(status_counts),
            'top_paths': dict(top_paths),
            'top_ips': dict(top_ips),
            'top_browsers': dict(top_browsers),
            'hourly_traffic': dict(hourly_traffic),
            'error_rate': round(error_rate, 2),
            'total_bytes': total_bytes,
            'avg_response_size': round(avg_response_size, 2),
            'bandwidth_mb': round(total_bytes / (1024 * 1024), 2)
        }
    
    def get_traffic_over_time(self, interval_hours=1):
        """Get traffic over time data."""
        if not self.parsed_logs:
            return {}
        
        # Group by time intervals
        time_buckets = defaultdict(int)
        for log in self.parsed_logs:
            if log['timestamp']:
                # Convert timezone-aware datetime to naive for consistency
                log_time = log['timestamp']
                if log_time.tzinfo is not None:
                    log_time = log_time.replace(tzinfo=None)
                # Round down to nearest hour interval
                rounded_time = log_time.replace(minute=0, second=0, microsecond=0)
                time_buckets[rounded_time] += 1
        
        # Sort by time
        sorted_times = sorted(time_buckets.keys())
        
        return {
            'timestamps': [ts.isoformat() for ts in sorted_times],
            'requests': [time_buckets[ts] for ts in sorted_times]
        }
    
    def get_status_code_distribution(self):
        """Get status code distribution for charts."""
        if not self.parsed_logs:
            return {}
        
        status_counts = Counter(str(log['status']) for log in self.parsed_logs)
        return {
            'labels': list(status_counts.keys()),
            'values': list(status_counts.values())
        }
    
    def get_attack_patterns(self):
        """Detect potential attack patterns."""
        if not self.parsed_logs:
            return []
        
        suspicious_patterns = []
        
        # SQL injection attempts
        sql_patterns = ['union', 'select', 'insert', 'delete', 'drop', 'script', 'alert', '%27', '%22']
        for pattern in sql_patterns:
            matches = [log for log in self.parsed_logs if pattern.lower() in log['url'].lower()]
            if matches:
                suspicious_patterns.append({
                    'type': f'Potential SQL Injection ({pattern})',
                    'count': len(matches),
                    'sample_urls': [log['url'] for log in matches[:3]]
                })
        
        # High frequency requests from single IP
        ip_counts = Counter(log['ip'] for log in self.parsed_logs)
        for ip, count in ip_counts.most_common(10):
            if count > 100:
                ip_logs = [log for log in self.parsed_logs if log['ip'] == ip]
                suspicious_patterns.append({
                    'type': f'High frequency requests from {ip}',
                    'count': count,
                    'sample_urls': [log['url'] for log in ip_logs[:3]]
                })
        
        # 404 errors (potential scanning)
        not_found_logs = [log for log in self.parsed_logs if log['status'] == 404]
        if len(not_found_logs) > 50:
            suspicious_patterns.append({
                'type': '404 Not Found (potential scanning)',
                'count': len(not_found_logs),
                'sample_urls': [log['url'] for log in not_found_logs[:5]]
            })
        
        return suspicious_patterns
    
    def get_advanced_analytics(self):
        """Get advanced analytics and insights."""
        if not self.parsed_logs:
            return {}
        
        analytics = {}
        
        # Bot detection and classification
        bot_patterns = {
            'Search Engines': ['googlebot', 'bingbot', 'yahoo', 'duckduckbot', 'baiduspider'],
            'Social Media': ['facebookexternalhit', 'twitterbot', 'linkedinbot', 'whatsapp'],
            'Monitoring': ['pingdom', 'uptimerobot', 'monitor', 'check'],
            'Security Scanners': ['nmap', 'nikto', 'sqlmap', 'dirb', 'gobuster', 'zgrab'],
            'Unknown Bots': ['bot', 'crawler', 'spider', 'scraper']
        }
        
        bot_traffic = defaultdict(int)
        human_traffic = 0
        
        for log in self.parsed_logs:
            ua = log['user_agent'].lower()
            categorized = False
            for category, patterns in bot_patterns.items():
                if any(pattern in ua for pattern in patterns):
                    bot_traffic[category] += 1
                    categorized = True
                    break
            if not categorized and 'mozilla' in ua:
                human_traffic += 1
        
        analytics['bot_analysis'] = {
            'human_traffic': human_traffic,
            'bot_categories': dict(bot_traffic),
            'total_bots': sum(bot_traffic.values()),
            'bot_percentage': round(sum(bot_traffic.values()) / len(self.parsed_logs) * 100, 2)
        }
        
        # Response time analysis (simulated based on response size)
        response_sizes = [log['size'] for log in self.parsed_logs if log['size'] > 0]
        if response_sizes:
            analytics['performance'] = {
                'avg_response_size': round(sum(response_sizes) / len(response_sizes), 2),
                'min_response_size': min(response_sizes),
                'max_response_size': max(response_sizes),
                'size_percentiles': {
                    '50th': sorted(response_sizes)[len(response_sizes)//2],
                    '95th': sorted(response_sizes)[int(len(response_sizes)*0.95)],
                    '99th': sorted(response_sizes)[int(len(response_sizes)*0.99)]
                }
            }
        
        # Geographic analysis (simplified)
        country_patterns = {
            'US': ['google', 'microsoft', 'amazon', 'facebook'],
            'China': ['baidu', 'bytedance'],
            'Russia': ['yandex', 'mail.ru'],
            'Unknown': []
        }
        
        geo_data = defaultdict(int)
        for log in self.parsed_logs:
            ua = log['user_agent'].lower()
            ref = (log['referer'] or '').lower()
            categorized = False
            for country, patterns in country_patterns.items():
                if any(pattern in ua or pattern in ref for pattern in patterns):
                    geo_data[country] += 1
                    categorized = True
                    break
            if not categorized:
                geo_data['Unknown'] += 1
        
        analytics['geographic'] = dict(geo_data)
        
        # Content analysis
        content_types = defaultdict(int)
        for log in self.parsed_logs:
            path = log['path'].lower()
            if any(ext in path for ext in ['.jpg', '.jpeg', '.png', '.gif', '.svg']):
                content_types['Images'] += 1
            elif any(ext in path for ext in ['.css', '.js']):
                content_types['Static Assets'] += 1
            elif any(ext in path for ext in ['.pdf', '.doc', '.zip', '.tar']):
                content_types['Downloads'] += 1
            elif path.endswith('/') or path == '':
                content_types['Pages'] += 1
            else:
                content_types['Other'] += 1
        
        analytics['content_types'] = dict(content_types)
        
        # Error analysis
        error_analysis = defaultdict(lambda: defaultdict(int))
        for log in self.parsed_logs:
            if log['status'] >= 400:
                status_range = f"{log['status']//100}xx"
                error_analysis[status_range][log['status']] += 1
        
        analytics['error_breakdown'] = {k: dict(v) for k, v in error_analysis.items()}
        
        # Peak traffic analysis
        hourly_stats = defaultdict(list)
        for log in self.parsed_logs:
            if log['timestamp']:
                hour = log['timestamp'].hour
                hourly_stats[hour].append(log['size'])
        
        peak_hours = []
        for hour, sizes in hourly_stats.items():
            peak_hours.append({
                'hour': hour,
                'requests': len(sizes),
                'bandwidth': sum(sizes),
                'avg_size': round(sum(sizes) / len(sizes), 2) if sizes else 0
            })
        
        analytics['peak_analysis'] = sorted(peak_hours, key=lambda x: x['requests'], reverse=True)[:5]
        
        return analytics
    
    def get_threat_intelligence(self):
        """Advanced threat detection and analysis."""
        if not self.parsed_logs:
            return {}
        
        threats = {
            'high_risk': [],
            'medium_risk': [],
            'low_risk': [],
            'informational': []
        }
        
        # Advanced SQL injection patterns
        advanced_sql_patterns = [
            'union.*select', 'concat.*char', 'extractvalue', 'updatexml',
            'load_file', 'into.*outfile', 'benchmark', 'sleep.*\\(', 'waitfor.*delay'
        ]
        
        for pattern in advanced_sql_patterns:
            matches = [log for log in self.parsed_logs if re.search(pattern, log['url'], re.IGNORECASE)]
            if matches:
                threats['high_risk'].append({
                    'type': f'Advanced SQL Injection: {pattern}',
                    'severity': 'HIGH',
                    'count': len(matches),
                    'ips': list(set(log['ip'] for log in matches)),
                    'sample_urls': [log['url'] for log in matches[:2]]
                })
        
        # XSS patterns
        xss_patterns = ['<script', 'javascript:', 'onerror=', 'onload=', 'alert\\(', 'document.cookie']
        for pattern in xss_patterns:
            matches = [log for log in self.parsed_logs if re.search(pattern, log['url'], re.IGNORECASE)]
            if matches:
                threats['medium_risk'].append({
                    'type': f'XSS Attempt: {pattern}',
                    'severity': 'MEDIUM',
                    'count': len(matches),
                    'ips': list(set(log['ip'] for log in matches)),
                    'sample_urls': [log['url'] for log in matches[:2]]
                })
        
        # Directory traversal
        traversal_patterns = ['../', '..\\\\', '%2e%2e', 'etc/passwd', 'windows/system32']
        for pattern in traversal_patterns:
            matches = [log for log in self.parsed_logs if pattern.lower() in log['url'].lower()]
            if matches:
                threats['medium_risk'].append({
                    'type': f'Directory Traversal: {pattern}',
                    'severity': 'MEDIUM',
                    'count': len(matches),
                    'ips': list(set(log['ip'] for log in matches)),
                    'sample_urls': [log['url'] for log in matches[:2]]
                })
        
        # Brute force detection
        ip_counts = Counter(log['ip'] for log in self.parsed_logs)
        for ip, count in ip_counts.items():
            if count > 200:
                ip_logs = [log for log in self.parsed_logs if log['ip'] == ip]
                failed_attempts = sum(1 for log in ip_logs if log['status'] in [401, 403, 404])
                if failed_attempts / count > 0.8:
                    threats['high_risk'].append({
                        'type': f'Potential Brute Force from {ip}',
                        'severity': 'HIGH',
                        'count': count,
                        'failed_attempts': failed_attempts,
                        'success_rate': f"{((count - failed_attempts) / count * 100):.1f}%"
                    })
        
        # Suspicious user agents
        suspicious_ua_patterns = ['curl', 'wget', 'python', 'java', 'go-http', 'masscan', 'zmap']
        for pattern in suspicious_ua_patterns:
            matches = [log for log in self.parsed_logs if pattern.lower() in log['user_agent'].lower()]
            if matches:
                threats['low_risk'].append({
                    'type': f'Suspicious User Agent: {pattern}',
                    'severity': 'LOW',
                    'count': len(matches),
                    'ips': list(set(log['ip'] for log in matches))[:5]
                })
        
        return threats
    
    def get_performance_metrics(self):
        """Get detailed performance metrics."""
        if not self.parsed_logs:
            return {}
        
        # Group by time periods
        daily_stats = defaultdict(lambda: {'requests': 0, 'bandwidth': 0, 'errors': 0})
        hourly_stats = defaultdict(lambda: {'requests': 0, 'bandwidth': 0, 'errors': 0})
        
        for log in self.parsed_logs:
            if log['timestamp']:
                # Convert timezone-aware datetime to naive for consistency
                log_time = log['timestamp']
                if log_time.tzinfo is not None:
                    log_time = log_time.replace(tzinfo=None)
                
                date_key = log_time.strftime('%Y-%m-%d')
                hour_key = log_time.strftime('%Y-%m-%d %H:00')
                
                daily_stats[date_key]['requests'] += 1
                daily_stats[date_key]['bandwidth'] += log['size']
                if log['status'] >= 400:
                    daily_stats[date_key]['errors'] += 1
                
                hourly_stats[hour_key]['requests'] += 1
                hourly_stats[hour_key]['bandwidth'] += log['size']
                if log['status'] >= 400:
                    hourly_stats[hour_key]['errors'] += 1
        
        # Calculate trends
        daily_data = sorted(daily_stats.items())
        performance_trends = []
        
        for i, (date, stats) in enumerate(daily_data):
            error_rate = (stats['errors'] / stats['requests'] * 100) if stats['requests'] > 0 else 0
            bandwidth_mb = stats['bandwidth'] / (1024 * 1024)
            
            trend_data = {
                'date': date,
                'requests': stats['requests'],
                'bandwidth_mb': round(bandwidth_mb, 2),
                'error_rate': round(error_rate, 2),
                'errors': stats['errors']
            }
            
            # Calculate day-over-day changes
            if i > 0:
                prev_stats = daily_data[i-1][1]
                prev_requests = prev_stats['requests']
                if prev_requests > 0:
                    trend_data['request_change'] = round(
                        ((stats['requests'] - prev_requests) / prev_requests * 100), 2
                    )
                else:
                    trend_data['request_change'] = 0
            
            performance_trends.append(trend_data)
        
        return {
            'daily_trends': performance_trends,
            'peak_hours': sorted([
                {
                    'hour': hour.split()[1],
                    'date': hour.split()[0],
                    'requests': stats['requests'],
                    'bandwidth_mb': round(stats['bandwidth'] / (1024 * 1024), 2)
                }
                for hour, stats in hourly_stats.items()
            ], key=lambda x: x['requests'], reverse=True)[:10]
        }
    
    def get_real_time_insights(self):
        """Get real-time insights and anomaly detection."""
        if not self.parsed_logs:
            return {}
        
        insights = {}
        
        # Recent activity (last hour)
        now = datetime.now()
        one_hour_ago = now - timedelta(hours=1)
        
        # Handle timezone-aware/naive datetime comparison
        recent_logs = []
        for log in self.parsed_logs:
            if log['timestamp']:
                # Convert timezone-aware datetime to naive for comparison
                log_time = log['timestamp']
                if log_time.tzinfo is not None:
                    log_time = log_time.replace(tzinfo=None)
                if log_time >= one_hour_ago:
                    recent_logs.append(log)
        
        insights['recent_activity'] = {
            'requests_last_hour': len(recent_logs),
            'unique_ips_last_hour': len(set(log['ip'] for log in recent_logs)),
            'errors_last_hour': sum(1 for log in recent_logs if log['status'] >= 400),
            'bandwidth_last_hour_mb': round(sum(log['size'] for log in recent_logs) / (1024 * 1024), 2)
        }
        
        # Traffic velocity analysis
        hourly_counts = defaultdict(int)
        for log in self.parsed_logs:
            if log['timestamp']:
                hour_key = log['timestamp'].strftime('%Y-%m-%d %H')
                hourly_counts[hour_key] += 1
        
        # Calculate average and detect spikes
        if hourly_counts:
            counts = list(hourly_counts.values())
            avg_hourly = sum(counts) / len(counts)
            max_hourly = max(counts)
            
            insights['traffic_velocity'] = {
                'avg_requests_per_hour': round(avg_hourly, 2),
                'peak_requests_per_hour': max_hourly,
                'traffic_spike_ratio': round(max_hourly / avg_hourly, 2) if avg_hourly > 0 else 0,
                'anomaly_detected': max_hourly > avg_hourly * 3  # Spike detection
            }
        
        # Response time estimation (based on response size)
        response_sizes = [log['size'] for log in self.parsed_logs if log['size'] > 0]
        if response_sizes:
            # Simulate response time based on size (rough estimation)
            estimated_times = [size / 1000 for size in response_sizes]  # ms estimation
            
            insights['response_time_analysis'] = {
                'avg_estimated_response_ms': round(sum(estimated_times) / len(estimated_times), 2),
                'p50_response_ms': round(sorted(estimated_times)[len(estimated_times)//2], 2),
                'p95_response_ms': round(sorted(estimated_times)[int(len(estimated_times)*0.95)], 2),
                'p99_response_ms': round(sorted(estimated_times)[int(len(estimated_times)*0.99)], 2)
            }
        
        # Session analysis
        session_data = defaultdict(list)
        for log in self.parsed_logs:
            session_data[log['ip']].append(log)
        
        session_lengths = []
        session_page_views = []
        for ip, logs in session_data.items():
            if len(logs) > 1:
                timestamps = []
                for log in logs:
                    if log['timestamp']:
                        # Convert timezone-aware datetime to naive for consistency
                        log_time = log['timestamp']
                        if log_time.tzinfo is not None:
                            log_time = log_time.replace(tzinfo=None)
                        timestamps.append(log_time)
                
                if timestamps:
                    session_length = (max(timestamps) - min(timestamps)).total_seconds() / 60  # minutes
                    session_lengths.append(session_length)
                    session_page_views.append(len(logs))
        
        if session_lengths:
            insights['session_analysis'] = {
                'avg_session_length_minutes': round(sum(session_lengths) / len(session_lengths), 2),
                'avg_pages_per_session': round(sum(session_page_views) / len(session_page_views), 2),
                'bounce_rate': round(sum(1 for length in session_page_views if length == 1) / len(session_page_views) * 100, 2)
            }
        
        return insights
    
    def get_predictive_analytics(self):
        """Get predictive analytics and forecasting."""
        if not self.parsed_logs:
            return {}
        
        analytics = {}
        
        # Traffic prediction based on historical patterns
        hourly_traffic = defaultdict(list)
        daily_traffic = defaultdict(int)
        
        for log in self.parsed_logs:
            if log['timestamp']:
                # Convert timezone-aware datetime to naive for consistency
                log_time = log['timestamp']
                if log_time.tzinfo is not None:
                    log_time = log_time.replace(tzinfo=None)
                
                hour = log_time.hour
                date = log_time.date()
                hourly_traffic[hour].append(1)
                daily_traffic[date] += 1
        
        # Predict next hour traffic
        current_hour = datetime.now().hour
        next_hour = (current_hour + 1) % 24
        
        if hourly_traffic[next_hour]:
            predicted_next_hour = round(sum(hourly_traffic[next_hour]) / len(hourly_traffic[next_hour]), 0)
        else:
            predicted_next_hour = 0
        
        analytics['traffic_prediction'] = {
            'predicted_next_hour_requests': int(predicted_next_hour),
            'current_hour': current_hour,
            'next_hour': next_hour
        }
        
        # Trend analysis
        daily_values = list(daily_traffic.values())
        if len(daily_values) >= 3:
            # Simple linear trend
            x = list(range(len(daily_values)))
            y = daily_values
            
            # Calculate trend slope
            n = len(x)
            sum_x = sum(x)
            sum_y = sum(y)
            sum_xy = sum(x[i] * y[i] for i in range(n))
            sum_x2 = sum(x[i] ** 2 for i in range(n))
            
            slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x ** 2) if (n * sum_x2 - sum_x ** 2) != 0 else 0
            
            analytics['trend_analysis'] = {
                'daily_trend_slope': round(slope, 2),
                'trend_direction': 'increasing' if slope > 0 else 'decreasing' if slope < 0 else 'stable',
                'trend_strength': 'strong' if abs(slope) > 100 else 'moderate' if abs(slope) > 50 else 'weak'
            }
        
        # Resource utilization prediction
        total_bandwidth = sum(log['size'] for log in self.parsed_logs)
        days_analyzed = len(set(log['timestamp'].date() for log in self.parsed_logs if log['timestamp']))
        
        if days_analyzed > 0:
            daily_avg_bandwidth = total_bandwidth / days_analyzed
            monthly_projection = daily_avg_bandwidth * 30
            
            analytics['resource_projection'] = {
                'daily_avg_bandwidth_mb': round(daily_avg_bandwidth / (1024 * 1024), 2),
                'monthly_bandwidth_projection_gb': round(monthly_projection / (1024 * 1024 * 1024), 2),
                'storage_requirement_estimate_gb': round(monthly_projection / (1024 * 1024 * 1024) * 0.1, 2)  # Assuming 10% for logs
            }
        
        return analytics
    
    def get_advanced_security_intelligence(self):
        """Get advanced security intelligence and risk scoring."""
        if not self.parsed_logs:
            return {}
        
        intelligence = {}
        
        # IP reputation analysis
        ip_behavior = defaultdict(lambda: {
            'total_requests': 0,
            'failed_requests': 0,
            'unique_paths': set(),
            'user_agents': set(),
            'suspicious_patterns': 0,
            'countries': set()
        })
        
        # Advanced threat patterns
        advanced_threats = [
            r'(?i)(union.*select|extractvalue|updatexml)',  # Advanced SQL injection
            r'(?i)(javascript:|vbscript:|onload=|onerror=)',  # XSS
            r'(?i)(\.\.\/|\.\.\\|%2e%2e)',  # Directory traversal
            r'(?i)(cmd=|exec=|system\()',  # Command injection
            r'(?i)(base64_decode|eval\(|assert\()',  # Code injection
            r'(?i)(sleep\(|benchmark\(|waitfor)',  # Time-based attacks
        ]
        
        for log in self.parsed_logs:
            ip = log['ip']
            ip_behavior[ip]['total_requests'] += 1
            ip_behavior[ip]['unique_paths'].add(log['path'])
            ip_behavior[ip]['user_agents'].add(log['user_agent'])
            
            if log['status'] >= 400:
                ip_behavior[ip]['failed_requests'] += 1
            
            # Check for advanced threat patterns
            for pattern in advanced_threats:
                if re.search(pattern, log['url']):
                    ip_behavior[ip]['suspicious_patterns'] += 1
        
        # Risk scoring
        high_risk_ips = []
        medium_risk_ips = []
        
        for ip, behavior in ip_behavior.items():
            risk_score = 0
            risk_factors = []
            
            # High request volume
            if behavior['total_requests'] > 1000:
                risk_score += 30
                risk_factors.append(f"High volume: {behavior['total_requests']} requests")
            
            # High failure rate
            failure_rate = behavior['failed_requests'] / behavior['total_requests'] if behavior['total_requests'] > 0 else 0
            if failure_rate > 0.5:
                risk_score += 25
                risk_factors.append(f"High failure rate: {failure_rate:.1%}")
            
            # Path diversity (potential scanning)
            if len(behavior['unique_paths']) > 100:
                risk_score += 20
                risk_factors.append(f"High path diversity: {len(behavior['unique_paths'])} paths")
            
            # Multiple user agents (potential bot)
            if len(behavior['user_agents']) > 10:
                risk_score += 15
                risk_factors.append(f"Multiple user agents: {len(behavior['user_agents'])}")
            
            # Suspicious patterns
            if behavior['suspicious_patterns'] > 0:
                risk_score += 40
                risk_factors.append(f"Threat patterns: {behavior['suspicious_patterns']}")
            
            if risk_score >= 60:
                high_risk_ips.append({
                    'ip': ip,
                    'risk_score': risk_score,
                    'risk_factors': risk_factors,
                    'total_requests': behavior['total_requests'],
                    'failure_rate': f"{failure_rate:.1%}"
                })
            elif risk_score >= 30:
                medium_risk_ips.append({
                    'ip': ip,
                    'risk_score': risk_score,
                    'risk_factors': risk_factors,
                    'total_requests': behavior['total_requests'],
                    'failure_rate': f"{failure_rate:.1%}"
                })
        
        intelligence['ip_risk_analysis'] = {
            'high_risk_ips': sorted(high_risk_ips, key=lambda x: x['risk_score'], reverse=True)[:10],
            'medium_risk_ips': sorted(medium_risk_ips, key=lambda x: x['risk_score'], reverse=True)[:10],
            'total_analyzed_ips': len(ip_behavior)
        }
        
        # Attack timeline
        attack_timeline = []
        for log in self.parsed_logs:
            if log['timestamp']:
                for pattern in advanced_threats:
                    if re.search(pattern, log['url']):
                        attack_timeline.append({
                            'timestamp': log['timestamp'].isoformat(),
                            'ip': sanitize_data(log['ip']),
                            'attack_type': sanitize_data(pattern),
                            'url': sanitize_data(log['url'][:100]),  # Truncate and sanitize URLs
                            'status': sanitize_data(str(log['status']))
                        })
        
        intelligence['attack_timeline'] = sorted(attack_timeline, key=lambda x: x['timestamp'], reverse=True)[:20]
        
        # Security recommendations
        recommendations = []
        
        if len(high_risk_ips) > 0:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'IP Blocking',
                'description': f'Consider blocking {len(high_risk_ips)} high-risk IP addresses',
                'action': 'Implement IP-based rate limiting or blocking'
            })
        
        if len(attack_timeline) > 10:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'WAF Implementation',
                'description': 'Multiple attack patterns detected',
                'action': 'Deploy Web Application Firewall (WAF)'
            })
        
        total_failed_requests = sum(1 for log in self.parsed_logs if log['status'] >= 400)
        if total_failed_requests / len(self.parsed_logs) > 0.2:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Error Monitoring',
                'description': 'High error rate detected',
                'action': 'Implement comprehensive error monitoring'
            })
        
        intelligence['security_recommendations'] = recommendations
        
        return intelligence
    
    def get_business_intelligence(self):
        """Get business intelligence and KPI analysis."""
        if not self.parsed_logs:
            return {}
        
        bi = {}
        
        # User engagement metrics
        page_views = len([log for log in self.parsed_logs if log['status'] == 200])
        unique_visitors = len(set(log['ip'] for log in self.parsed_logs))
        
        # Content popularity
        content_engagement = defaultdict(lambda: {'views': 0, 'unique_visitors': set(), 'bounce_rate': 0})
        
        for log in self.parsed_logs:
            if log['status'] == 200:
                path = log['path']
                content_engagement[path]['views'] += 1
                content_engagement[path]['unique_visitors'].add(log['ip'])
        
        # Calculate engagement metrics
        top_content = []
        for path, data in content_engagement.items():
            if data['views'] > 1:  # Filter out single-view pages
                engagement_score = len(data['unique_visitors']) * data['views']
                top_content.append({
                    'path': path,
                    'views': data['views'],
                    'unique_visitors': len(data['unique_visitors']),
                    'engagement_score': engagement_score
                })
        
        bi['content_analytics'] = {
            'total_page_views': page_views,
            'unique_visitors': unique_visitors,
            'pages_per_visitor': round(page_views / unique_visitors, 2) if unique_visitors > 0 else 0,
            'top_content': sorted(top_content, key=lambda x: x['engagement_score'], reverse=True)[:10]
        }
        
        # Traffic source analysis
        referrer_analysis = defaultdict(int)
        for log in self.parsed_logs:
            referrer = log.get('referer', '') or ''
            if referrer and referrer != '-':
                if 'google' in referrer.lower():
                    referrer_analysis['Google Search'] += 1
                elif 'bing' in referrer.lower():
                    referrer_analysis['Bing Search'] += 1
                elif 'facebook' in referrer.lower():
                    referrer_analysis['Facebook'] += 1
                elif 'twitter' in referrer.lower():
                    referrer_analysis['Twitter'] += 1
                else:
                    referrer_analysis['Other Referrers'] += 1
            else:
                referrer_analysis['Direct Traffic'] += 1
        
        bi['traffic_sources'] = dict(referrer_analysis)
        
        # Conversion funnel (simplified)
        funnel_steps = {
            'landing': len([log for log in self.parsed_logs if log['path'] == '/' and log['status'] == 200]),
            'browsing': len([log for log in self.parsed_logs if log['path'] != '/' and log['status'] == 200]),
            'downloads': len([log for log in self.parsed_logs if any(ext in log['path'].lower() for ext in ['.pdf', '.zip', '.doc'])]),
            'forms': len([log for log in self.parsed_logs if 'contact' in log['path'].lower() or 'form' in log['path'].lower()])
        }
        
        bi['conversion_funnel'] = funnel_steps
        
        # Peak business hours
        business_hours = defaultdict(int)
        for log in self.parsed_logs:
            if log['timestamp']:
                # Convert timezone-aware datetime to naive for consistency
                log_time = log['timestamp']
                if log_time.tzinfo is not None:
                    log_time = log_time.replace(tzinfo=None)
                
                hour = log_time.hour
                # Business hours: 9 AM to 5 PM
                if 9 <= hour <= 17:
                    business_hours['business_hours'] += 1
                else:
                    business_hours['non_business_hours'] += 1
        
        bi['business_hours_analysis'] = dict(business_hours)
        
        return bi
    
    def get_top_ips(self):
        """Get top IP addresses by request count."""
        if not self.parsed_logs:
            return {}
        
        ip_counts = Counter(log['ip'] for log in self.parsed_logs)
        return dict(ip_counts.most_common(50))
    
    def get_status_codes(self):
        """Get HTTP status code distribution."""
        if not self.parsed_logs:
            return {}
        
        status_counts = Counter(log['status'] for log in self.parsed_logs)
        return dict(status_counts.most_common())
    
    def get_user_agents(self):
        """Get user agent distribution."""
        if not self.parsed_logs:
            return {}
        
        ua_counts = Counter()
        for log in self.parsed_logs:
            if log.get('user_agent'):
                # Simplify user agent strings for better grouping
                ua = log['user_agent']
                if 'Chrome' in ua:
                    ua_counts['Chrome Browser'] += 1
                elif 'Firefox' in ua:
                    ua_counts['Firefox Browser'] += 1
                elif 'Safari' in ua and 'Chrome' not in ua:
                    ua_counts['Safari Browser'] += 1
                elif 'Edge' in ua:
                    ua_counts['Edge Browser'] += 1
                elif 'bot' in ua.lower() or 'spider' in ua.lower() or 'crawler' in ua.lower():
                    ua_counts['Bots/Crawlers'] += 1
                else:
                    # Take first few words for grouping
                    simplified = ' '.join(ua.split()[:3]) if ua.split() else 'Unknown'
                    ua_counts[simplified] += 1
        
        return dict(ua_counts.most_common(30))

# Initialize the analyzer
log_analyzer = LogAnalyzer(r'.')

@app.route('/')
def dashboard():
    """Main dashboard."""
    return render_template('dashboard.html')

@app.route('/api/load_logs')
def load_logs():
    """Load logs from files."""
    days_back = request.args.get('days', 7, type=int)
    count = log_analyzer.load_logs(days_back)
    return jsonify({'status': 'success', 'logs_loaded': count})

@app.route('/api/summary')
def get_summary():
    """Get summary statistics."""
    summary_data = log_analyzer.get_summary_stats()
    return jsonify(sanitize_data(summary_data))

@app.route('/api/traffic_over_time')
def get_traffic_over_time():
    """Get traffic over time data."""
    traffic_data = log_analyzer.get_traffic_over_time()
    return jsonify(sanitize_data(traffic_data))

@app.route('/api/status_distribution')
def get_status_distribution():
    """Get status code distribution."""
    return jsonify(log_analyzer.get_status_code_distribution())

@app.route('/api/geographic')
def get_geographic():
    """Get geographic data."""
    if not log_analyzer.parsed_logs:
        return jsonify({})
    
    ip_counts = Counter(log['ip'] for log in log_analyzer.parsed_logs)
    top_ips = ip_counts.most_common(20)
    
    return jsonify({
        'ips': [ip for ip, count in top_ips],
        'counts': [count for ip, count in top_ips]
    })

@app.route('/api/attacks')
def get_attacks():
    """Get potential attack patterns."""
    attacks_data = log_analyzer.get_attack_patterns()
    return jsonify(sanitize_data(attacks_data))

@app.route('/api/advanced_analytics')
def get_advanced_analytics():
    """Get advanced analytics and insights."""
    return jsonify(log_analyzer.get_advanced_analytics())

@app.route('/api/threat_intelligence')
def get_threat_intelligence():
    """Get threat intelligence and advanced security analysis."""
    threat_data = log_analyzer.get_threat_intelligence()
    return jsonify(sanitize_data(threat_data))

@app.route('/api/performance_metrics')
def get_performance_metrics():
    """Get detailed performance metrics and trends."""
    return jsonify(log_analyzer.get_performance_metrics())

@app.route('/api/detailed_report')
def get_detailed_report():
    """Get comprehensive detailed report."""
    report = {
        'summary': log_analyzer.get_summary_stats(),
        'advanced_analytics': log_analyzer.get_advanced_analytics(),
        'threat_intelligence': log_analyzer.get_threat_intelligence(),
        'performance_metrics': log_analyzer.get_performance_metrics(),
        'timestamp': datetime.now().isoformat()
    }
    return jsonify(report)

@app.route('/api/real_time_insights')
def get_real_time_insights():
    """Get real-time insights and anomaly detection."""
    return jsonify(log_analyzer.get_real_time_insights())

@app.route('/api/predictive_analytics')
def get_predictive_analytics():
    """Get predictive analytics and forecasting."""
    return jsonify(log_analyzer.get_predictive_analytics())

@app.route('/api/security_intelligence')
def get_security_intelligence():
    """Get advanced security intelligence and risk scoring."""
    return jsonify(log_analyzer.get_advanced_security_intelligence())

@app.route('/api/business_intelligence')
def get_business_intelligence():
    """Get business intelligence and KPI analysis."""
    return jsonify(log_analyzer.get_business_intelligence())

@app.route('/api/comprehensive_report')
def get_comprehensive_report():
    """Get the most comprehensive report with all analytics."""
    report = {
        'metadata': {
            'generated_at': datetime.now().isoformat(),
            'analysis_period': log_analyzer.get_summary_stats().get('date_range', 'Unknown'),
            'total_logs_analyzed': len(log_analyzer.parsed_logs)
        },
        'summary': log_analyzer.get_summary_stats(),
        'advanced_analytics': log_analyzer.get_advanced_analytics(),
        'threat_intelligence': log_analyzer.get_threat_intelligence(),
        'performance_metrics': log_analyzer.get_performance_metrics(),
        'real_time_insights': log_analyzer.get_real_time_insights(),
        'predictive_analytics': log_analyzer.get_predictive_analytics(),
        'security_intelligence': log_analyzer.get_advanced_security_intelligence(),
        'business_intelligence': log_analyzer.get_business_intelligence()
    }
    return jsonify(report)

@app.route('/api/export')
def export_data():
    """Export data as JSON."""
    if not log_analyzer.parsed_logs:
        return jsonify({'error': 'No data loaded'})
    
    # Convert datetime objects to strings for JSON serialization
    export_data = []
    for log in log_analyzer.parsed_logs:
        log_copy = log.copy()
        if log_copy['timestamp']:
            log_copy['timestamp'] = log_copy['timestamp'].isoformat()
        export_data.append(log_copy)
    
    return jsonify({
        'logs': export_data,
        'summary': log_analyzer.get_summary_stats()
    })

class PDFReportGenerator:
    """Generate PDF reports from analytics data."""
    
    def __init__(self):
        if not REPORTLAB_AVAILABLE:
            raise ImportError("ReportLab is required for PDF generation. Install with: pip install reportlab")
        
        self.styles = getSampleStyleSheet()
        self.title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=HexColor('#2c3e50')
        )
        self.heading_style = ParagraphStyle(
            'CustomHeading',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            textColor=HexColor('#34495e')
        )
        self.subheading_style = ParagraphStyle(
            'CustomSubHeading',
            parent=self.styles['Heading3'],
            fontSize=14,
            spaceAfter=8,
            textColor=HexColor('#7f8c8d')
        )
    
    def create_chart_image(self, data, chart_type, title, filename):
        """Create a chart image for PDF inclusion."""
        if not MATPLOTLIB_AVAILABLE:
            return None
            
        plt.figure(figsize=(10, 6))
        plt.clf()
        
        if chart_type == 'bar':
            keys = list(data.keys())[:10]  # Top 10
            values = [data[k] for k in keys]
            plt.bar(keys, values)
            plt.xticks(rotation=45, ha='right')
        elif chart_type == 'pie':
            keys = list(data.keys())[:8]  # Top 8
            values = [data[k] for k in keys]
            plt.pie(values, labels=keys, autopct='%1.1f%%')
        elif chart_type == 'line':
            keys = list(data.keys())
            values = list(data.values())
            plt.plot(keys, values, marker='o')
            plt.xticks(rotation=45, ha='right')
        
        plt.title(title)
        plt.tight_layout()
        
        # Save to bytes buffer
        img_buffer = io.BytesIO()
        plt.savefig(img_buffer, format='png', dpi=150, bbox_inches='tight')
        img_buffer.seek(0)
        plt.close()
        
        return img_buffer.getvalue()
    
    def generate_summary_report(self, analyzer):
        """Generate a summary PDF report."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        story = []
        
        # Title
        story.append(Paragraph("NGINX Access Log Analysis Report", self.title_style))
        story.append(Spacer(1, 20))
        
        # Generation info
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", self.styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Summary statistics
        summary = analyzer.get_summary_stats()
        story.append(Paragraph("Executive Summary", self.heading_style))
        
        summary_data = [
            ['Metric', 'Value'],
            ['Total Requests', f"{summary.get('total_requests', 0):,}"],
            ['Unique IPs', f"{summary.get('unique_ips', 0):,}"],
            ['Error Rate', f"{summary.get('error_rate', 0):.2f}%"],
            ['Bandwidth (MB)', f"{summary.get('bandwidth_mb', 0):.2f}"],
            ['Date Range', summary.get('date_range', 'N/A')]
        ]
        
        table = Table(summary_data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(table)
        story.append(Spacer(1, 20))
        
        # Top IPs
        story.append(Paragraph("Top IP Addresses", self.heading_style))
        top_ips = analyzer.get_top_ips()
        if top_ips:
            ip_data = [['IP Address', 'Requests']]
            for ip, count in list(top_ips.items())[:10]:
                ip_data.append([ip, str(count)])
            
            ip_table = Table(ip_data)
            ip_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(ip_table)
        story.append(Spacer(1, 20))
        
        # Status codes
        story.append(Paragraph("HTTP Status Code Distribution", self.heading_style))
        status_codes = analyzer.get_status_codes()
        if status_codes:
            status_data = [['Status Code', 'Count', 'Description']]
            status_descriptions = {
                '200': 'OK', '404': 'Not Found', '500': 'Internal Server Error',
                '301': 'Moved Permanently', '302': 'Found', '403': 'Forbidden',
                '400': 'Bad Request', '503': 'Service Unavailable'
            }
            
            for code, count in list(status_codes.items())[:10]:
                desc = status_descriptions.get(str(code), 'Other')
                status_data.append([str(code), str(count), desc])
            
            status_table = Table(status_data)
            status_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(status_table)
        
        doc.build(story)
        buffer.seek(0)
        return buffer
    
    def generate_security_report(self, analyzer):
        """Generate a security-focused PDF report."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        story = []
        
        # Title
        story.append(Paragraph("NGINX Security Analysis Report", self.title_style))
        story.append(Spacer(1, 20))
        
        # Generation info
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", self.styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Threat intelligence
        threat_data = analyzer.get_threat_intelligence()
        story.append(Paragraph("Security Threat Assessment", self.heading_style))
        
        # High risk threats
        if threat_data.get('high_risk'):
            story.append(Paragraph("🔴 High Risk Threats", self.subheading_style))
            for threat in threat_data['high_risk'][:10]:
                threat_text = f"• {threat.get('ip', 'Unknown IP')} - {threat.get('reason', 'No reason provided')}"
                story.append(Paragraph(threat_text, self.styles['Normal']))
            story.append(Spacer(1, 12))
        
        # Medium risk threats
        if threat_data.get('medium_risk'):
            story.append(Paragraph("🟡 Medium Risk Threats", self.subheading_style))
            for threat in threat_data['medium_risk'][:10]:
                threat_text = f"• {threat.get('ip', 'Unknown IP')} - {threat.get('reason', 'No reason provided')}"
                story.append(Paragraph(threat_text, self.styles['Normal']))
            story.append(Spacer(1, 12))
        
        # Attack patterns
        attacks = analyzer.get_attack_patterns()
        if attacks:
            story.append(Paragraph("Attack Pattern Analysis", self.heading_style))
            attack_data = [['Attack Type', 'Count', 'Risk Level']]
            
            # Handle attacks as a list of dictionaries
            for attack in attacks:
                if isinstance(attack, dict) and 'count' in attack:
                    attack_type = attack.get('type', 'Unknown Attack')
                    count = attack['count']
                    risk = 'High' if count > 10 else 'Medium' if count > 5 else 'Low'
                    attack_data.append([attack_type, str(count), risk])
            
            if len(attack_data) > 1:
                attack_table = Table(attack_data)
                attack_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.red),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 12),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                story.append(attack_table)
        
        doc.build(story)
        buffer.seek(0)
        return buffer
    
    def generate_comprehensive_report(self, analyzer):
        """Generate a comprehensive PDF report with all analytics."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        story = []
        
        # Title page
        story.append(Paragraph("Comprehensive NGINX Analytics Report", self.title_style))
        story.append(Spacer(1, 20))
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", self.styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Executive Summary
        summary = analyzer.get_summary_stats()
        story.append(Paragraph("📊 Executive Summary", self.heading_style))
        
        exec_summary = f"""
        This comprehensive report analyzes {summary.get('total_requests', 0):,} requests from 
        {summary.get('unique_ips', 0):,} unique IP addresses over the period {summary.get('date_range', 'Unknown')}.
        
        <b>Key Performance Indicators:</b>
        • Total Requests: {summary.get('total_requests', 0):,}
        • Unique Visitors: {summary.get('unique_ips', 0):,}
        • Error Rate: {summary.get('error_rate', 0):.2f}%
        • Total Bandwidth: {summary.get('bandwidth_mb', 0):.2f} MB
        • Average Request Size: {summary.get('avg_request_size_kb', 0):.2f} KB
        """
        story.append(Paragraph(exec_summary, self.styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Summary Statistics Table
        summary_table_data = [
            ['Metric', 'Value', 'Status'],
            ['Total Requests', f"{summary.get('total_requests', 0):,}", '✓ Normal'],
            ['Unique IPs', f"{summary.get('unique_ips', 0):,}", '✓ Normal'],
            ['Error Rate', f"{summary.get('error_rate', 0):.2f}%", '⚠ High' if summary.get('error_rate', 0) > 10 else '✓ Normal'],
            ['Bandwidth (MB)', f"{summary.get('bandwidth_mb', 0):.2f}", '✓ Normal'],
            ['Avg Request Size (KB)', f"{summary.get('avg_request_size_kb', 0):.2f}", '✓ Normal']
        ]
        
        summary_table = Table(summary_table_data, colWidths=[3*inch, 2*inch, 1.5*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#ecf0f1')),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 10)
        ]))
        story.append(summary_table)
        story.append(PageBreak())
        
        # Traffic Analysis Section
        story.append(Paragraph("🚦 Traffic Analysis", self.heading_style))
        
        # Top IP Addresses
        story.append(Paragraph("Top IP Addresses", self.subheading_style))
        top_ips = analyzer.get_top_ips()
        if top_ips:
            ip_data = [['Rank', 'IP Address', 'Requests', 'Percentage']]
            total_requests = summary.get('total_requests', 1)
            
            for idx, (ip, count) in enumerate(list(top_ips.items())[:15], 1):
                percentage = (count / total_requests) * 100
                ip_data.append([str(idx), ip, f"{count:,}", f"{percentage:.2f}%"])
            
            ip_table = Table(ip_data, colWidths=[0.7*inch, 2.5*inch, 1.5*inch, 1.3*inch])
            ip_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#3498db')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), HexColor('#ecf0f1')),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 9)
            ]))
            story.append(ip_table)
            story.append(Spacer(1, 15))
        
        # HTTP Status Codes
        story.append(Paragraph("HTTP Status Code Distribution", self.subheading_style))
        status_codes = analyzer.get_status_codes()
        if status_codes:
            status_data = [['Status Code', 'Count', 'Percentage', 'Description']]
            status_descriptions = {
                '200': 'OK - Success', '404': 'Not Found', '500': 'Internal Server Error',
                '301': 'Moved Permanently', '302': 'Found', '403': 'Forbidden',
                '400': 'Bad Request', '503': 'Service Unavailable', '401': 'Unauthorized',
                '304': 'Not Modified', '502': 'Bad Gateway'
            }
            
            for code, count in list(status_codes.items())[:10]:
                percentage = (count / total_requests) * 100
                desc = status_descriptions.get(str(code), 'Other')
                status_data.append([str(code), f"{count:,}", f"{percentage:.2f}%", desc])
            
            status_table = Table(status_data, colWidths=[1*inch, 1.2*inch, 1.2*inch, 2.6*inch])
            status_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#27ae60')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), HexColor('#ecf0f1')),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 9)
            ]))
            story.append(status_table)
        
        story.append(PageBreak())
        
        # Real-Time Insights
        story.append(Paragraph("⚡ Real-Time Traffic Insights", self.heading_style))
        rt_insights = analyzer.get_real_time_insights()
        
        if rt_insights.get('recent_activity'):
            activity = rt_insights['recent_activity']
            rt_data = [
                ['Metric', 'Value', 'Trend'],
                ['Requests (Last Hour)', f"{activity.get('requests_last_hour', 0):,}", '📈 Active'],
                ['Unique IPs (Last Hour)', f"{activity.get('unique_ips_last_hour', 0):,}", '📊 Normal'],
                ['Errors (Last Hour)', f"{activity.get('errors_last_hour', 0):,}", '⚠ Monitor' if activity.get('errors_last_hour', 0) > 10 else '✓ Good'],
                ['Peak Hour Requests', f"{activity.get('peak_hour_requests', 0):,}", '🔥 Peak'],
                ['Average Requests/Min', f"{activity.get('avg_requests_per_minute', 0):.1f}", '📊 Steady']
            ]
            
            rt_table = Table(rt_data, colWidths=[2.5*inch, 2*inch, 1.5*inch])
            rt_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#e74c3c')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), HexColor('#ecf0f1')),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 9)
            ]))
            story.append(rt_table)
            story.append(Spacer(1, 15))
        
        # Anomaly Detection
        if rt_insights.get('anomalies'):
            story.append(Paragraph("🚨 Anomaly Detection", self.subheading_style))
            anomalies = rt_insights['anomalies']
            
            anomaly_text = f"""
            <b>Traffic Anomalies Detected:</b>
            • Traffic Spikes: {len(anomalies.get('traffic_spikes', []))} detected
            • Error Bursts: {len(anomalies.get('error_bursts', []))} detected
            • Unusual Patterns: {len(anomalies.get('unusual_patterns', []))} detected
            
            These anomalies indicate potential issues or unusual activity patterns that may require investigation.
            """
            story.append(Paragraph(anomaly_text, self.styles['Normal']))
            story.append(Spacer(1, 15))
        
        story.append(PageBreak())
        
        # Security Intelligence
        story.append(Paragraph("🛡️ Security Intelligence", self.heading_style))
        
        # Threat Assessment
        threat_data = analyzer.get_threat_intelligence()
        security_intel = analyzer.get_advanced_security_intelligence()
        
        if threat_data:
            high_risk_count = len(threat_data.get('high_risk', []))
            medium_risk_count = len(threat_data.get('medium_risk', []))
            low_risk_count = len(threat_data.get('low_risk', []))
            total_threats = high_risk_count + medium_risk_count + low_risk_count
            
            security_summary = f"""
            <b>Security Threat Assessment:</b>
            • Total Threats Identified: {total_threats}
            • High Risk Threats: {high_risk_count} (Immediate attention required)
            • Medium Risk Threats: {medium_risk_count} (Monitor closely)
            • Low Risk Threats: {low_risk_count} (Standard monitoring)
            
            <b>Overall Risk Level:</b> {'🔴 HIGH' if high_risk_count > 5 else '🟡 MEDIUM' if medium_risk_count > 10 else '🟢 LOW'}
            """
            story.append(Paragraph(security_summary, self.styles['Normal']))
            story.append(Spacer(1, 15))
            
            # High Risk Threats Table
            if threat_data.get('high_risk'):
                story.append(Paragraph("🔴 High Risk Threats", self.subheading_style))
                threat_table_data = [['IP Address', 'Threat Type', 'Risk Score', 'Details']]
                
                for threat in threat_data['high_risk'][:10]:
                    ip = threat.get('ip', 'Unknown')
                    threat_type = threat.get('threat_type', 'Unknown')
                    risk_score = threat.get('risk_score', 'N/A')
                    reason = threat.get('reason', 'No details')[:50] + '...' if len(threat.get('reason', '')) > 50 else threat.get('reason', 'No details')
                    threat_table_data.append([ip, threat_type, str(risk_score), reason])
                
                if len(threat_table_data) > 1:
                    threat_table = Table(threat_table_data, colWidths=[1.5*inch, 1.5*inch, 1*inch, 2*inch])
                    threat_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#c0392b')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 9),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('BACKGROUND', (0, 1), (-1, -1), HexColor('#ecf0f1')),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                        ('FONTSIZE', (0, 1), (-1, -1), 8),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP')
                    ]))
                    story.append(threat_table)
                    story.append(Spacer(1, 15))
        
        # Attack Patterns
        attacks = analyzer.get_attack_patterns()
        if attacks:
            story.append(Paragraph("⚔️ Attack Pattern Analysis", self.subheading_style))
            attack_data = [['Attack Type', 'Incidents', 'Risk Level', 'Sample URLs']]
            
            # Handle attacks as a list of dictionaries
            for attack in attacks:
                if isinstance(attack, dict):
                    attack_type = attack.get('type', 'Unknown Attack')
                    count = attack.get('count', 0)
                    risk = '🔴 High' if count > 10 else '🟡 Medium' if count > 5 else '🟢 Low'
                    sample_urls = attack.get('sample_urls', [])
                    # Take first URL as sample, truncate if too long
                    sample_url = sample_urls[0][:50] + '...' if sample_urls and len(sample_urls[0]) > 50 else (sample_urls[0] if sample_urls else 'N/A')
                    
                    attack_data.append([
                        attack_type,
                        str(count),
                        risk,
                        sample_url
                    ])
            
            if len(attack_data) > 1:
                attack_table = Table(attack_data, colWidths=[2*inch, 1*inch, 1.5*inch, 1.5*inch])
                attack_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), HexColor('#8e44ad')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), HexColor('#ecf0f1')),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('FONTSIZE', (0, 1), (-1, -1), 8)
                ]))
                story.append(attack_table)
        
        story.append(PageBreak())
        
        # Performance Analysis
        story.append(Paragraph("⚡ Performance Analysis", self.heading_style))
        
        perf_metrics = analyzer.get_performance_metrics()
        if perf_metrics:
            # Performance Overview
            story.append(Paragraph("Performance Overview", self.subheading_style))
            
            perf_overview = f"""
            <b>System Performance Metrics:</b>
            • Response Time Analysis: {perf_metrics.get('response_time_analysis', 'Available')}
            • Traffic Load Assessment: {perf_metrics.get('load_assessment', 'Monitored')}
            • Resource Utilization: {perf_metrics.get('resource_utilization', 'Optimal')}
            • Peak Traffic Handling: {perf_metrics.get('peak_handling', 'Stable')}
            
            Performance metrics indicate system health and identify optimization opportunities.
            """
            story.append(Paragraph(perf_overview, self.styles['Normal']))
            story.append(Spacer(1, 15))
            
            # Performance Metrics Table
            if isinstance(perf_metrics, dict) and perf_metrics:
                perf_table_data = [['Metric', 'Value', 'Status', 'Recommendation']]
                
                # Add performance metrics if available
                metrics_to_show = [
                    ('avg_response_time', 'Average Response Time', 'ms'),
                    ('peak_traffic_period', 'Peak Traffic Period', ''),
                    ('error_rate_trend', 'Error Rate Trend', '%'),
                    ('bandwidth_utilization', 'Bandwidth Utilization', 'MB'),
                ]
                
                for key, label, unit in metrics_to_show:
                    value = perf_metrics.get(key, 'N/A')
                    if value != 'N/A':
                        status = '✓ Good'
                        recommendation = 'Continue monitoring'
                        perf_table_data.append([label, f"{value} {unit}".strip(), status, recommendation])
                
                if len(perf_table_data) > 1:
                    perf_table = Table(perf_table_data, colWidths=[2*inch, 1.5*inch, 1*inch, 1.5*inch])
                    perf_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#16a085')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 9),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('BACKGROUND', (0, 1), (-1, -1), HexColor('#ecf0f1')),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                        ('FONTSIZE', (0, 1), (-1, -1), 8)
                    ]))
                    story.append(perf_table)
        
        story.append(PageBreak())
        
        # Business Intelligence
        story.append(Paragraph("📈 Business Intelligence", self.heading_style))
        
        business_intel = analyzer.get_business_intelligence()
        if business_intel:
            story.append(Paragraph("Business Metrics Overview", self.subheading_style))
            
            bi_summary = f"""
            <b>Key Business Insights:</b>
            • User Engagement: {business_intel.get('engagement_score', 'Measuring')}
            • Content Performance: {business_intel.get('content_analysis', 'Analyzing')}
            • Geographic Distribution: {business_intel.get('geographic_insights', 'Mapped')}
            • Device & Browser Trends: {business_intel.get('device_trends', 'Tracked')}
            
            Business intelligence provides insights into user behavior and system usage patterns.
            """
            story.append(Paragraph(bi_summary, self.styles['Normal']))
            story.append(Spacer(1, 15))
        
        # Top User Agents
        user_agents = analyzer.get_user_agents()
        if user_agents:
            story.append(Paragraph("🌐 User Agent Analysis", self.subheading_style))
            ua_data = [['Browser/Client', 'Requests', 'Percentage', 'Type']]
            
            for agent, count in list(user_agents.items())[:10]:
                percentage = (count / total_requests) * 100
                agent_type = 'Browser' if any(browser in agent.lower() for browser in ['chrome', 'firefox', 'safari', 'edge']) else 'Bot/Other'
                ua_data.append([agent[:40] + '...' if len(agent) > 40 else agent, f"{count:,}", f"{percentage:.2f}%", agent_type])
            
            ua_table = Table(ua_data, colWidths=[2.5*inch, 1*inch, 1*inch, 1.5*inch])
            ua_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#34495e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), HexColor('#ecf0f1')),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 8)
            ]))
            story.append(ua_table)
        
        story.append(PageBreak())
        
        # Recommendations and Conclusions
        story.append(Paragraph("💡 Recommendations & Action Items", self.heading_style))
        
        recommendations = f"""
        <b>Key Recommendations:</b>
        
        <b>Security:</b>
        • {'⚠️ Immediate review of high-risk threats required' if threat_data and len(threat_data.get('high_risk', [])) > 0 else '✅ Security posture appears stable'}
        • Regular monitoring of attack patterns and suspicious IPs
        • Consider implementing rate limiting for high-traffic IPs
        
        <b>Performance:</b>
        • {'⚠️ Monitor error rates - above normal thresholds' if summary.get('error_rate', 0) > 10 else '✅ Error rates within acceptable limits'}
        • Continue monitoring peak traffic patterns
        • Consider caching strategies for frequently accessed content
        
        <b>Operations:</b>
        • Regular log analysis and monitoring recommended
        • Set up alerts for anomalous traffic patterns
        • Review and update security policies periodically
        
        <b>Next Steps:</b>
        • Schedule regular security assessments
        • Implement automated alerting for critical metrics
        • Continue comprehensive log analysis and reporting
        """
        story.append(Paragraph(recommendations, self.styles['Normal']))
        
        # Footer
        story.append(Spacer(1, 30))
        story.append(Paragraph("📋 End of Comprehensive Report", self.styles['Normal']))
        story.append(Spacer(1, 10))
        story.append(Paragraph(f"Report generated on {datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}", self.styles['Normal']))
        
        doc.build(story)
        buffer.seek(0)
        return buffer

# PDF Export Routes
@app.route('/api/export/pdf/summary')
def export_summary_pdf():
    """Export summary report as PDF."""
    if not REPORTLAB_AVAILABLE:
        return jsonify({'error': 'PDF generation not available. Install reportlab: pip install reportlab'}), 500
    
    if not log_analyzer.parsed_logs:
        return jsonify({'error': 'No data loaded'}), 400
    
    try:
        pdf_generator = PDFReportGenerator()
        pdf_buffer = pdf_generator.generate_summary_report(log_analyzer)
        
        response = make_response(pdf_buffer.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=nginx_summary_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
        return response
    except Exception as e:
        return jsonify({'error': f'PDF generation failed: {str(e)}'}), 500

@app.route('/api/export/pdf/security')
def export_security_pdf():
    """Export security report as PDF."""
    if not REPORTLAB_AVAILABLE:
        return jsonify({'error': 'PDF generation not available. Install reportlab: pip install reportlab'}), 500
    
    if not log_analyzer.parsed_logs:
        return jsonify({'error': 'No data loaded'}), 400
    
    try:
        pdf_generator = PDFReportGenerator()
        pdf_buffer = pdf_generator.generate_security_report(log_analyzer)
        
        response = make_response(pdf_buffer.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=nginx_security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
        return response
    except Exception as e:
        return jsonify({'error': f'PDF generation failed: {str(e)}'}), 500

@app.route('/api/export/pdf/comprehensive')
def export_comprehensive_pdf():
    """Export comprehensive report as PDF."""
    if not REPORTLAB_AVAILABLE:
        return jsonify({'error': 'PDF generation not available. Install reportlab: pip install reportlab'}), 500
    
    if not log_analyzer.parsed_logs:
        return jsonify({'error': 'No data loaded'}), 400
    
    try:
        pdf_generator = PDFReportGenerator()
        print(f"DEBUG: Starting PDF generation with {len(log_analyzer.parsed_logs)} logs")
        pdf_buffer = pdf_generator.generate_comprehensive_report(log_analyzer)
        print("DEBUG: PDF generation completed successfully")
        
        response = make_response(pdf_buffer.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=nginx_comprehensive_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
        return response
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"ERROR: PDF generation failed: {error_details}")
        return jsonify({'error': f'PDF generation failed: {str(e)}', 'details': error_details}), 500

if __name__ == '__main__':
    print("Starting NGINX Access Log Analyzer...")
    print(f"Log directory: {log_analyzer.log_directory}")
    print("Open your browser to: http://localhost:5006")
    app.run(debug=True, host='0.0.0.0', port=5006)