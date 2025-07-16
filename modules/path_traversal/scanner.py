# modules/path_traversal/scanner.py
import requests
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
import os
from core.utils.logger import CyberLogger

class PathTraversalScanner:
    def __init__(self):
        self.logger = CyberLogger()
        self.payloads_file = os.path.join("resources", "payloads", "traversal", "traversal_payloads.txt")
        self.payloads = self._load_payloads()
        self.vulnerable_responses = [
            "root:x:",  # Linux /etc/passwd signature
            "[fonts]",  # Windows win.ini signature
            "Directory Listing For", # Common directory listing message
            "Index of /", # Another common directory listing message
            "c:\\windows\\system32", # Windows system path
            "/bin/bash", # Linux binary path
        ]

    def _load_payloads(self):
        """Loads path traversal payloads from the specified file."""
        payloads = []
        try:
            with open(self.payloads_file, 'r', encoding='utf-8') as f:
                for line in f:
                    payload = line.strip()
                    if payload and not payload.startswith('#'):
                        payloads.append(payload)
            self.logger.info(f"Loaded {len(payloads)} path traversal payloads from {self.payloads_file}")
        except FileNotFoundError:
            self.logger.error(f"Payloads file not found: {self.payloads_file}. Please ensure it exists.")
        except Exception as e:
            self.logger.error(f"Error loading payloads from {self.payloads_file}: {e}")
        return payloads

    def _build_test_url(self, base_url, param, payload):
        """Builds a URL with the given payload injected into a parameter."""
        parsed_url = urlparse(base_url)
        query_params = parse_qs(parsed_url.query)
        
        # Modify the specific parameter with the payload
        if param in query_params:
            # We are testing by appending to the *value* of the parameter
            original_value = query_params[param][0] # Assuming single value for simplicity
            query_params[param] = original_value + payload
        else:
            # If the parameter doesn't exist in query, assume it's part of the path (less common for this fuzzer)
            # This fuzzer is primarily for query parameters.
            self.logger.debug(f"Parameter '{param}' not found in query string for {base_url}. Skipping path injection.")
            return None

        new_query = urlencode(query_params, doseq=True) # Re-encode query parameters
        return urlunparse(parsed_url._replace(query=new_query))

    def _check_vulnerability(self, response):
        """Checks the response for signs of a successful path traversal."""
        # Check for 200 OK status code, and specific content in the response body
        if response.status_code == 200:
            for signature in self.vulnerable_responses:
                if signature.lower() in response.text.lower():
                    self.logger.warning(f"Potential Path Traversal: Found signature '{signature}' in response.")
                    return True
        # Also check for 400/500 series errors that might reveal server paths
        elif 400 <= response.status_code < 600:
            for signature in self.vulnerable_responses:
                 if signature.lower() in response.text.lower():
                    self.logger.warning(f"Potential Path Traversal (Error Code {response.status_code}): Found signature '{signature}' in response.")
                    return True
        return False

    def scan(self, target_url):
        """
        Scans a target URL for path traversal vulnerabilities.
        It identifies parameters and tests each with payloads.
        :param target_url: The URL to scan (e.g., "http://example.com/file.php?name=test").
        :return: A list of dicts, each representing a found vulnerability.
        """
        self.logger.info(f"Starting Path Traversal scan for: {target_url}")
        vulnerabilities = []
        parsed_url = urlparse(target_url)
        query_params = parse_qs(parsed_url.query)

        if not self.payloads:
            self.logger.error("No payloads loaded. Aborting scan.")
            return []
        
        if not query_params:
            self.logger.info(f"No query parameters found in {target_url}. Path Traversal scan primarily targets parameters.")
            self.logger.info("Consider manually testing path-based traversal if applicable (e.g., http://example.com/download/file.php)")
            return []

        for param in query_params:
            self.logger.info(f"Testing parameter: '{param}'")
            for payload in self.payloads:
                test_url = self._build_test_url(target_url, param, payload)
                if test_url is None:
                    continue # Skip if parameter wasn't in query string for injection
                    
                self.logger.debug(f"Trying payload: {payload} on {param} -> {test_url}")
                try:
                    response = requests.get(test_url, timeout=10) # Added timeout
                    if self._check_vulnerability(response):
                        vuln_details = {
                            "vulnerability": "Path Traversal",
                            "url": test_url,
                            "parameter": param,
                            "payload_used": payload,
                            "response_status": response.status_code,
                            "response_snippet": response.text[:200] + "..." if len(response.text) > 200 else response.text
                        }
                        vulnerabilities.append(vuln_details)
                        self.logger.success(f"Path Traversal vulnerability found: {test_url}")
                        # Optional: break if one vulnerability found per param, or continue to find all
                        # break 
                except requests.exceptions.RequestException as e:
                    self.logger.error(f"Request error during Path Traversal scan for {test_url}: {e}")
                except Exception as e:
                    self.logger.error(f"An unexpected error occurred during Path Traversal scan: {e}")
        
        if not vulnerabilities:
            self.logger.info(f"No Path Traversal vulnerabilities found for {target_url}.")
        
        return vulnerabilities

# --- For direct testing of this module ---
if __name__ == '__main__':
    # Set up basic logging for standalone test
    import logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    print("--- Testing PathTraversalScanner ---")
    scanner = PathTraversalScanner()

    # --- Test 1: Vulnerable URL Example (conceptual, replace with actual if available) ---
    # This URL is just an example for demonstration; you'd need a truly vulnerable site
    # For a real test, you'd target a web application with a parameter that loads files.
    # Example: http://example.com/download.php?file=document.pdf
    # Vulnerable scenarios often involve parameters like 'file', 'page', 'template', 'view', 'path', etc.
    
    # You can use a local setup or a known vulnerable Docker container (e.g., OWASP Juice Shop, DVWA)
    # This example assumes a fictional vulnerable parameter 'filename'
    test_target_vulnerable = "http://localhost:8080/download?filename=image.jpg"
    # To simulate a vulnerable response for testing:
    # Temporarily modify _check_vulnerability to always return True for this test or mock requests.
    
    # Example for a real test (if you have DVWA/local vulnerable app running):
    # test_target_dvwa = "http://127.0.0.1/vulnerabilities/fi/?page=include.php" 
    # (Ensure DVWA is running on File Inclusion Low/Medium/High)

    print(f"\n--- Scanning (simulated) vulnerable URL: {test_target_vulnerable} ---")
    # For a real test, the response from test_target_vulnerable + payload should contain vulnerable_responses signatures
    # If you run DVWA, use: python modules/path_traversal/scanner.py
    # Then input the DVWA URL with FI vuln like http://127.0.0.1/vulnerabilities/fi/?page=include.php
    
    # Note: If running this directly without a truly vulnerable target, it will likely report "No Path Traversal vulnerabilities found."
    # To see it "work" without a vulnerable server, you'd need to mock the requests.
    
    # For a quick manual check of the scanner's logic flow, you can run this block.
    # The vulnerability will only be reported if a signature from `vulnerable_responses` is found.
    # It's highly recommended to test this against a controlled vulnerable environment like DVWA or a custom lab.

    found_vulnerabilities = scanner.scan(test_target_vulnerable)
    
    if found_vulnerabilities:
        print("\n--- Path Traversal Scan Results ---")
        for vuln in found_vulnerabilities:
            print(f"  Vulnerability: {vuln['vulnerability']}")
            print(f"  URL: {vuln['url']}")
            print(f"  Parameter: {vuln['parameter']}")
            print(f"  Payload Used: {vuln['payload_used']}")
            print(f"  Response Status: {vuln['response_status']}")
            print(f"  Response Snippet: {vuln['response_snippet']}")
            print("-" * 30)
    else:
        print("\nNo Path Traversal vulnerabilities detected for the test URL.")