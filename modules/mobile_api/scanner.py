# modules/mobile_api/scanner.py
import requests
import json
from urllib.parse import urljoin
from core.utils.logger import CyberLogger

class MobileAPITester:
    def __init__(self):
        self.logger = CyberLogger()
        self.session = requests.Session() # Use a session to maintain cookies
        # Add common mobile-like headers (can be customized)
        self.default_headers = {
            "User-Agent": "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.58 Mobile Safari/537.36",
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        self.success_statuses = [200, 201, 204]
        self.unauthorized_statuses = [401, 403]

    def _make_request(self, url, method="GET", headers=None, data=None, json_data=None):
        """Helper to make HTTP requests with default mobile-like headers."""
        combined_headers = self.default_headers.copy()
        if headers:
            combined_headers.update(headers)
            
        try:
            if method.upper() == "POST":
                response = self.session.post(url, headers=combined_headers, data=data, json=json_data, timeout=10)
            elif method.upper() == "PUT":
                response = self.session.put(url, headers=combined_headers, data=data, json=json_data, timeout=10)
            elif method.upper() == "DELETE":
                response = self.session.delete(url, headers=combined_headers, timeout=10)
            else: # Default to GET
                response = self.session.get(url, headers=combined_headers, timeout=10)
            
            # response.raise_for_status() # Do not raise for status here, we want to check 401/403
            return response
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Mobile API request failed for {url} ({method}): {e}")
            return None

    def test_unauthenticated_access(self, api_endpoint, sensitive_data_keywords=None):
        """
        Tests if a given API endpoint can be accessed without authentication (e.g., for sensitive data).
        
        :param api_endpoint: The full URL of the API endpoint to test (e.g., "https://api.example.com/v1/users/profile").
        :param sensitive_data_keywords: List of keywords to look for in response indicating sensitive data leakage.
        :return: A list of dicts, each representing an unauthenticated access vulnerability.
        """
        self.logger.info(f"Testing unauthenticated access for: {api_endpoint}")
        vulnerabilities = []

        response = self._make_request(api_endpoint, method="GET", headers={}) # Empty headers for unauthenticated test

        if response is None:
            self.logger.warning(f"Could not get a response from {api_endpoint}. Skipping unauthenticated test.")
            return []

        if response.status_code in self.success_statuses:
            self.logger.success(f"Potential Unauthenticated Access vulnerability: {api_endpoint} returned {response.status_code} (Expected 401/403).")
            details = f"Endpoint accessible without authentication. Status code: {response.status_code}."
            
            response_text = response.text
            if sensitive_data_keywords:
                found_keywords = [kw for kw in sensitive_data_keywords if kw.lower() in response_text.lower()]
                if found_keywords:
                    details += f" Sensitive data keywords found: {', '.join(found_keywords)}."
            
            vulnerabilities.append({
                "vulnerability": "Unauthenticated Access to Sensitive Mobile API Endpoint",
                "url": api_endpoint,
                "method": "GET",
                "response_status": response.status_code,
                "details": details,
                "response_snippet": response_text[:200] + "..." if len(response_text) > 200 else response_text
            })
        elif response.status_code in self.unauthorized_statuses:
            self.logger.info(f"Access to {api_endpoint} denied as expected (Status: {response.status_code}). Protected.")
        else:
            self.logger.info(f"Access to {api_endpoint} returned status: {response.status_code}. Further investigation needed.")

        if not vulnerabilities:
            self.logger.info(f"No unauthenticated access vulnerabilities found for {api_endpoint}.")
        
        return vulnerabilities

    def scan(self, scan_type="unauthenticated_access", **kwargs):
        """
        Main entry point for Mobile API security scans.
        :param scan_type: Type of mobile API scan to perform (e.g., "unauthenticated_access").
        :param kwargs: Arguments specific to the scan type.
        """
        if scan_type == "unauthenticated_access":
            return self.test_unauthenticated_access(**kwargs)
        else:
            self.logger.error(f"Unknown Mobile API scan type: {scan_type}")
            return []


# --- For direct testing of this module ---
if __name__ == '__main__':
    # Set up basic logging for standalone test
    import logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    print("--- Testing MobileAPITester ---")
    tester = MobileAPITester()

    # --- Test 1: Example Unauthenticated Access Scan ---
    # To properly test this, you'd need:
    # 1. A web application with an API endpoint meant for mobile apps.
    # 2. This endpoint should ideally require authentication but
    #    be vulnerable to direct unauthenticated access.
    
    # Example: A (hypothetically vulnerable) user data endpoint
    # Target structure: http://localhost:PORT/mobile-api/v1/user/data
    
    # NOTE: This example will likely NOT find a vulnerability unless you have
    # a specifically vulnerable API endpoint running locally.

    test_api_endpoint = "http://localhost/mobile-api/v1/user/data" 
    sensitive_keywords = ["email", "address", "phone", "credit_card", "social_security"]
    
    print(f"\n--- Scanning Mobile API for Unauthenticated Access: {test_api_endpoint} ---")
    found_vulnerabilities = tester.scan(
        scan_type="unauthenticated_access",
        api_endpoint=test_api_endpoint,
        sensitive_data_keywords=sensitive_keywords
    )
    
    if found_vulnerabilities:
        print("\n--- Mobile API Security Scan Results (Unauthenticated Access) ---")
        for vuln in found_vulnerabilities:
            print(f"  Vulnerability: {vuln['vulnerability']}")
            print(f"  URL: {vuln['url']}")
            print(f"  Response Status: {vuln['response_status']}")
            print(f"  Details: {vuln['details']}")
            print(f"  Response Snippet: {vuln['response_snippet']}")
            print("-" * 30)
    else:
        print("\nNo unauthenticated access vulnerabilities detected for the test Mobile API endpoint.")