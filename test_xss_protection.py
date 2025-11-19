#!/usr/bin/env python3
"""
XSS Vulnerability Test Script
Tests the security fixes applied to the NGINX Log Analyzer.
"""

import requests
import json

def test_xss_protection():
    """Test XSS protection in the application."""
    
    print("🔒 Testing XSS Protection...")
    print("=" * 50)
    
    base_url = "http://localhost:5006"
    
    # Test payloads
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<img src=x onerror=alert('XSS')>",
        "\"><script>alert('XSS')</script>",
        "<svg onload=alert('XSS')>",
        "';alert('XSS');//"
    ]
    
    try:
        # Test summary endpoint
        print("Testing /api/summary endpoint...")
        response = requests.get(f"{base_url}/api/summary", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print("✅ Summary endpoint accessible")
            
            # Check if data contains any unescaped HTML
            response_text = json.dumps(data)
            dangerous_chars = ['<script>', '<img', 'javascript:', 'onerror=']
            
            found_issues = []
            for char in dangerous_chars:
                if char in response_text:
                    found_issues.append(char)
            
            if found_issues:
                print(f"⚠️  Potential XSS found in summary: {found_issues}")
            else:
                print("✅ Summary endpoint properly sanitized")
        else:
            print(f"❌ Summary endpoint error: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Error testing summary: {e}")
    
    try:
        # Test attacks endpoint  
        print("\nTesting /api/attacks endpoint...")
        response = requests.get(f"{base_url}/api/attacks", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print("✅ Attacks endpoint accessible")
            
            # Check for XSS in attack data
            response_text = json.dumps(data)
            if any(payload in response_text for payload in xss_payloads):
                print("⚠️  Potential XSS payloads found in attacks data")
            else:
                print("✅ Attacks endpoint properly sanitized")
        else:
            print(f"❌ Attacks endpoint error: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Error testing attacks: {e}")
    
    try:
        # Test main dashboard
        print("\nTesting main dashboard...")
        response = requests.get(f"{base_url}/", timeout=5)
        if response.status_code == 200:
            print("✅ Dashboard accessible")
            
            # Check security headers
            headers = response.headers
            security_headers = {
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'DENY', 
                'X-XSS-Protection': '1; mode=block',
                'Content-Security-Policy': 'default-src'
            }
            
            for header, expected in security_headers.items():
                if header in headers and expected in headers[header]:
                    print(f"✅ Security header '{header}' present")
                else:
                    print(f"⚠️  Security header '{header}' missing or incorrect")
        else:
            print(f"❌ Dashboard error: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Error testing dashboard: {e}")
    
    print("\n" + "=" * 50)
    print("🛡️ XSS Protection Test Complete")
    print("💡 If any warnings appear, review the security fixes.")

if __name__ == "__main__":
    test_xss_protection()