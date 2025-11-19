#!/usr/bin/env python3
"""
Create test log with XSS payloads to verify protection
This script creates log entries with malicious XSS payloads to test our protection.
"""

import os

def create_malicious_log():
    """Create a test log with XSS payloads."""
    
    malicious_entries = [
        # Standard log entries
        '127.0.0.1 - - [05/Nov/2025:10:00:00 +0000] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"',
        '127.0.0.1 - - [05/Nov/2025:10:01:00 +0000] "GET /api/summary HTTP/1.1" 200 567 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"',
        
        # XSS in URLs
        '192.168.1.100 - - [05/Nov/2025:10:02:00 +0000] "GET /<script>alert(\'XSS\')</script> HTTP/1.1" 404 0 "-" "Mozilla/5.0"',
        '192.168.1.100 - - [05/Nov/2025:10:03:00 +0000] "GET /search?q=<img src=x onerror=alert(\'XSS\')> HTTP/1.1" 200 890 "-" "Mozilla/5.0"',
        '192.168.1.100 - - [05/Nov/2025:10:04:00 +0000] "GET /page?data=javascript:alert(\'XSS\') HTTP/1.1" 200 500 "-" "Mozilla/5.0"',
        
        # XSS in User-Agent
        '10.0.0.1 - - [05/Nov/2025:10:05:00 +0000] "GET /normal HTTP/1.1" 200 200 "-" "Mozilla<script>alert(\'XSS\')</script>"',
        '10.0.0.1 - - [05/Nov/2025:10:06:00 +0000] "GET /test HTTP/1.1" 200 300 "-" "Evil\\"onclick=alert(\'XSS\')Browser"',
        
        # XSS in referrer
        '172.16.1.1 - - [05/Nov/2025:10:07:00 +0000] "GET /page HTTP/1.1" 200 400 "http://evil.com/<script>alert(\'XSS\')</script>" "Mozilla/5.0"',
        
        # SQL injection attempts (also potential XSS)
        '203.0.113.1 - - [05/Nov/2025:10:08:00 +0000] "GET /login?user=admin\'--<script>alert(\'XSS\')</script> HTTP/1.1" 403 0 "-" "curl/7.68.0"',
        
        # More sophisticated XSS
        '198.51.100.1 - - [05/Nov/2025:10:09:00 +0000] "GET /search?q=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E HTTP/1.1" 200 600 "-" "Mozilla/5.0"',
        
        # Normal entries to dilute
        '127.0.0.1 - - [05/Nov/2025:10:10:00 +0000] "GET /assets/style.css HTTP/1.1" 200 1500 "http://localhost:5006/" "Mozilla/5.0"',
        '127.0.0.1 - - [05/Nov/2025:10:11:00 +0000] "GET /api/attacks HTTP/1.1" 200 234 "-" "Mozilla/5.0"',
    ]
    
    log_path = 'access.log'
    
    with open(log_path, 'w') as f:
        for entry in malicious_entries:
            f.write(entry + '\n')
    
    print(f"✅ Created malicious test log: {log_path}")
    print(f"📊 Total entries: {len(malicious_entries)}")
    print(f"🚨 XSS payloads: {len([e for e in malicious_entries if 'script' in e.lower() or 'alert' in e.lower()])}")

def create_clean_log():
    """Create a clean test log without XSS."""
    
    clean_entries = [
        '127.0.0.1 - - [05/Nov/2025:10:00:00 +0000] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"',
        '127.0.0.1 - - [05/Nov/2025:10:01:00 +0000] "GET /api/summary HTTP/1.1" 200 567 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"',
        '192.168.1.100 - - [05/Nov/2025:10:02:00 +0000] "GET /dashboard HTTP/1.1" 200 2345 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"',
        '192.168.1.100 - - [05/Nov/2025:10:03:00 +0000] "POST /api/load_logs HTTP/1.1" 200 890 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"',
        '10.0.0.1 - - [05/Nov/2025:10:04:00 +0000] "GET /static/css/style.css HTTP/1.1" 200 1500 "http://localhost:5006/" "Mozilla/5.0"',
        '172.16.1.1 - - [05/Nov/2025:10:05:00 +0000] "GET /api/attacks HTTP/1.1" 200 234 "-" "Mozilla/5.0"',
    ]
    
    log_path = 'access_clean.log'
    
    with open(log_path, 'w') as f:
        for entry in clean_entries:
            f.write(entry + '\n')
    
    print(f"✅ Created clean test log: {log_path}")
    print(f"📊 Total entries: {len(clean_entries)}")

if __name__ == "__main__":
    print("🛡️ Creating test logs for XSS protection verification...")
    print("=" * 60)
    
    create_malicious_log()
    print()
    create_clean_log()
    
    print("\n" + "=" * 60)
    print("📝 Instructions:")
    print("1. Rename 'access.log' to test with malicious payloads")
    print("2. Rename 'access_clean.log' to 'access.log' for safe testing")
    print("3. Start the application and check for XSS alerts")
    print("4. All XSS payloads should be safely escaped and not executed")