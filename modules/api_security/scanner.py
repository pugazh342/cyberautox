# modules/api_security/scanner.py
import requests
from urllib.parse import urlparse, urljoin
import json
from core.utils.logger import CyberLogger

class APISecurityScanner:
    def __init__(self):
        self.logger = CyberLogger()
        self.session = requests.Session() # Use a session to maintain cookies
        # Common API success indicators (can be customized)
        self.success_statuses = [200, 201, 204]
        # Common API error indicators
        self.error_statuses = [400, 401, 403, 404, 500]

    def _make_api_request(self, url, method="GET", headers=None, data=None, json_data=None):
        """Helper to make API requests."""
        try:
            if method.upper() == "POST":
                response = self.session.post(url, headers=headers, data=data, json=json_data, timeout=10)
            elif method.upper() == "PUT":
                response = self.session.put(url, headers=headers, data=data, json=json_data, timeout=10)
            elif method.upper() == "DELETE":
                response = self.session.delete(url, headers=headers, timeout=10)
            else: # Default to GET
                response = self.session.get(url, headers=headers, timeout=10)
            
            response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
            return response
        except requests.exceptions.RequestException as e:
            self.logger.error(f"API request failed for {url} ({method}): {e}")
            return None

    def scan_bola(self, base_api_url, vulnerable_endpoint_pattern, initial_id="1", test_ids=["2", "999", "admin"]):
        """
        Scans for Broken Object Level Authorization (BOLA).
        Attempts to access other resource IDs.
        
        :param base_api_url: The base URL of the API (e.g., "https://api.example.com/v1/").
        :param vulnerable_endpoint_pattern: A pattern for a known vulnerable endpoint with an ID placeholder.
                                            Use '{}' for the ID. E.g., "users/{}" or "products/{}".
        :param initial_id: An ID that is expected to be accessible (e.g., the current user's ID).
        :param test_ids: A list of IDs to test for unauthorized access.
        :return: A list of dicts, each representing a found BOLA vulnerability.
        """
        self.logger.info(f"Starting BOLA scan for API endpoint: {base_api_url}/{vulnerable_endpoint_pattern}")
        vulnerabilities = []

        # First, try to access the initial ID to establish a baseline
        initial_url = urljoin(base_api_url, vulnerable_endpoint_pattern.format(initial_id))
        self.logger.info(f"Testing baseline access to: {initial_url}")
        initial_response = self._make_api_request(initial_url)

        if initial_response and initial_response.status_code in self.success_statuses:
            self.logger.info(f"Baseline (ID {initial_id}) accessible. Status: {initial_response.status_code}")
            # The actual content of the baseline can be used for comparison
            # initial_data = initial_response.json() if initial_response.headers.get('Content-Type') == 'application/json' else initial_response.text
        else:
            self.logger.warning(f"Baseline (ID {initial_id}) not accessible or failed. Status: {initial_response.status_code if initial_response else 'N/A'}")
            # If the initial ID is not accessible, the BOLA test might not be relevant or needs a valid session.
            return []
        
        # Now, try to access other IDs
        self.logger.info(f"Attempting to access other IDs: {', '.join(test_ids)}")
        for test_id in test_ids:
            if str(test_id) == str(initial_id): # Skip if it's the same as initial_id
                continue 

            test_url = urljoin(base_api_url, vulnerable_endpoint_pattern.format(test_id))
            self.logger.info(f"Testing unauthorized access to: {test_url}")
            test_response = self._make_api_request(test_url)

            if test_response and test_response.status_code in self.success_statuses:
                # If we successfully accessed an ID that we shouldn't have been able to
                self.logger.success(f"Potential BOLA vulnerability: Accessed ID '{test_id}' via {test_url}")
                vulnerabilities.append({
                    "vulnerability": "Broken Object Level Authorization (BOLA)",
                    "url": test_url,
                    "method": "GET", # Assuming GET for this simple BOLA check
                    "test_id": test_id,
                    "details": f"Successfully accessed resource for ID '{test_id}' which should have been restricted. Response status: {test_response.status_code}",
                    "response_snippet": test_response.text[:200] + "..." if len(test_response.text) > 200 else test_response.text
                })
            elif test_response and test_response.status_code in [401, 403]:
                self.logger.info(f"Access to ID '{test_id}' denied as expected (Status: {test_response.status_code}). Protected.")
            else:
                self.logger.info(f"Access to ID '{test_id}' resulted in status: {test_response.status_code if test_response else 'N/A'}.")

        if not vulnerabilities:
            self.logger.info(f"No BOLA vulnerabilities found for {base_api_url}/{vulnerable_endpoint_pattern}.")
        
        return vulnerabilities

    # You can add more scan methods here, e.g., for BFLA, unauthenticated access, rate limiting etc.
    def scan(self, api_type="bola", **kwargs):
        """
        Main entry point for API security scans.
        :param api_type: Type of API scan to perform (e.g., "bola").
        :param kwargs: Arguments specific to the scan type.
        """
        if api_type == "bola":
            return self.scan_bola(**kwargs)
        else:
            self.logger.error(f"Unknown API scan type: {api_type}")
            return []


# --- For direct testing of this module ---
if __name__ == '__main__':
    # Set up basic logging for standalone test
    import logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    print("--- Testing APISecurityScanner ---")
    scanner = APISecurityScanner()

    # --- Test 1: Example BOLA Scan ---
    # To properly test BOLA, you'd need:
    # 1. A web application with an API endpoint that uses IDs in the URL.
    # 2. That endpoint should reveal sensitive information when accessed with a different user's ID without proper authorization checks.
    # 3. Often, you'd first need to log in to get a valid session (cookies/tokens) if the API requires authentication.
    
    # Example: A (hypothetically vulnerable) user profile API endpoint
    # Target structure: http://localhost:PORT/api/v1/users/{id}
    
    # NOTE: This example will likely NOT find a vulnerability unless you have
    # a specifically vulnerable API endpoint running locally.
    
    # If you have a DVWA-like setup with an API, you might adapt.
    # For a real test, you'd typically login first to establish the session.
    # scanner.session.post("http://localhost/login.php", data={"username": "user", "password": "password"})

    # Replace with your actual API endpoint and IDs for testing
    api_url = "http://localhost/api/v1/" # Base API URL
    endpoint_pattern = "users/{}"       # The endpoint pattern with ID placeholder
    
    # '1' is the ID for the user currently logged in (hypothetically)
    # '2' and 'admin' are IDs you try to access illicitly
    
    # You might want to adjust initial_id and test_ids based on your target's user IDs.
    
    print(f"\n--- Scanning API for BOLA: {api_url}{endpoint_pattern} ---")
    found_vulnerabilities = scanner.scan(
        api_type="bola",
        base_api_url=api_url,
        vulnerable_endpoint_pattern=endpoint_pattern,
        initial_id="1",
        test_ids=["2", "3", "4", "5", "100", "admin"] # Example IDs to try
    )
    
    if found_vulnerabilities:
        print("\n--- API Security Scan Results (BOLA) ---")
        for vuln in found_vulnerabilities:
            print(f"  Vulnerability: {vuln['vulnerability']}")
            print(f"  URL: {vuln['url']}")
            print(f"  Tested ID: {vuln['test_id']}")
            print(f"  Details: {vuln['details']}")
            print(f"  Response Status: {vuln['response_status']}")
            print(f"  Response Snippet: {vuln['response_snippet']}")
            print("-" * 30)
    else:
        print("\nNo BOLA vulnerabilities detected for the test API endpoint.")