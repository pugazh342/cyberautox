# modules/session_attack/scanner.py
import requests
import re
from collections import Counter
from core.utils.logger import CyberLogger

class SessionAttacker:
    def __init__(self):
        self.logger = CyberLogger()
        self.session = requests.Session()
        self.login_success_keywords = ["welcome", "dashboard", "logout"] # Keywords indicating successful login
        self.unauthorized_statuses = [401, 403]
        self.success_statuses = [200, 302] # 302 for redirects after login

    def _make_request(self, url, method="GET", headers=None, data=None, json_data=None, cookies=None, allow_redirects=True):
        """Helper to make HTTP requests."""
        try:
            response = self.session.request(method.upper(), url, headers=headers, data=data, json=json_data, cookies=cookies, allow_redirects=allow_redirects, timeout=10)
            return response
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Session attack request failed for {url} ({method}): {e}")
            return None

    def _extract_session_id(self, response, cookie_name="PHPSESSID"):
        """Extracts a session ID from the response cookies."""
        if response and response.cookies:
            for cookie in response.cookies:
                if cookie.name == cookie_name:
                    return cookie.value
        return None

    def test_predictable_session_ids(self, 
                                     login_url, 
                                     username_field, 
                                     password_field, 
                                     username, 
                                     password, 
                                     num_attempts=10, 
                                     cookie_name="PHPSESSID"):
        """
        Tests for predictable session IDs by generating multiple sessions and analyzing them.
        
        :param login_url: The URL of the login page.
        :param username_field: The name attribute of the username input field.
        :param password_field: The name attribute of the password input field.
        :param username: The username to use for login attempts.
        :param password: The password to use for login attempts.
        :param num_attempts: Number of times to attempt login and capture session IDs.
        :param cookie_name: The name of the session cookie to extract (e.g., 'PHPSESSID', 'JSESSIONID').
        :return: A list of dicts, each representing a found predictable session ID vulnerability.
        """
        self.logger.info(f"Testing for predictable session IDs on {login_url} (Cookie: {cookie_name})")
        vulnerabilities = []
        captured_session_ids = []

        self.logger.info(f"Attempting to capture {num_attempts} session IDs...")
        for i in range(num_attempts):
            # Reset session for each attempt to get a new session ID
            self.session = requests.Session() 
            
            # First, make a GET request to the login page to get initial cookies and CSRF tokens if any
            initial_response = self._make_request(login_url, method="GET")
            if initial_response is None:
                self.logger.error(f"Failed to get initial response from {login_url}. Skipping session ID prediction test.")
                return []

            # Prepare login data
            login_data = {
                username_field: username,
                password_field: password
            }
            # Extract any CSRF token from the initial response if present (basic example)
            csrf_token_match = re.search(r'<input[^>]+name=["\']user_token["\'][^>]+value=["\']([^"\']+)["\']', initial_response.text)
            if csrf_token_match:
                login_data['user_token'] = csrf_token_match.group(1)
                self.logger.info(f"Extracted CSRF token: {login_data['user_token'][:10]}...") # Log snippet

            # Send login request
            login_response = self._make_request(login_url, method="POST", data=login_data, cookies=initial_response.cookies)

            if login_response and login_response.status_code in self.success_statuses:
                if any(keyword in login_response.text.lower() for keyword in self.login_success_keywords):
                    session_id = self._extract_session_id(login_response, cookie_name)
                    if session_id:
                        captured_session_ids.append(session_id)
                        self.logger.info(f"Attempt {i+1}/{num_attempts}: Captured Session ID: {session_id[:10]}...") # Log snippet
                    else:
                        self.logger.warning(f"Attempt {i+1}/{num_attempts}: No session ID found in cookies for {cookie_name}.")
                else:
                    self.logger.warning(f"Attempt {i+1}/{num_attempts}: Login successful (Status: {login_response.status_code}), but no success keywords found in response. Verify login success detection.")
            else:
                self.logger.warning(f"Attempt {i+1}/{num_attempts}: Login failed or unexpected status ({login_response.status_code if login_response else 'N/A'}).")

        if len(captured_session_ids) < num_attempts:
            self.logger.warning(f"Only captured {len(captured_session_ids)} out of {num_attempts} session IDs. Results might not be reliable.")
            if not captured_session_ids:
                self.logger.info("No session IDs were captured successfully. Cannot perform predictability test.")
                return []

        # Analyze predictability (simple check for now: look for non-random patterns, or identical IDs)
        if len(set(captured_session_ids)) < len(captured_session_ids):
            # If there are duplicates, it's a strong indicator of predictability/session fixation
            self.logger.success(f"Potential Session Vulnerability: Duplicate session IDs observed. Found {len(captured_session_ids) - len(set(captured_session_ids))} duplicate(s) out of {len(captured_session_ids)} captured.")
            vulnerabilities.append({
                "vulnerability": "Predictable Session ID / Session Fixation (Duplicates)",
                "url": login_url,
                "details": f"Multiple login attempts yielded identical or very similar session IDs. Captured IDs: {Counter(captured_session_ids)}",
                "captured_ids_count": Counter(captured_session_ids)
            })
        else:
            self.logger.info(f"Captured {len(captured_session_ids)} unique session IDs. Further entropy analysis would be required for full predictability assessment.")
            # For a more advanced scan, you'd integrate entropy analysis (e.g., using a statistical test on the bit string of the IDs)

        if not vulnerabilities:
            self.logger.info(f"No obvious predictable session ID vulnerabilities found for {login_url}.")
        
        return vulnerabilities

    def scan(self, scan_type="predictable_session_ids", **kwargs):
        """
        Main entry point for Session Attack scans.
        :param scan_type: Type of session attack scan to perform (e.g., "predictable_session_ids").
        :param kwargs: Arguments specific to the scan type.
        """
        if scan_type == "predictable_session_ids":
            return self.test_predictable_session_ids(**kwargs)
        else:
            self.logger.error(f"Unknown Session Attack scan type: {scan_type}")
            return []


# --- For direct testing of this module ---
if __name__ == '__main__':
    # Set up basic logging for standalone test
    import logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    print("--- Testing SessionAttacker ---")
    scanner = SessionAttacker()

    # --- Test 1: Example Predictable Session ID Scan ---
    # To properly test this, you'd need:
    # 1. A web application with a login form that issues session cookies.
    # 2. This application should ideally issue predictable or fixed session IDs.
    
    # Example: A (hypothetically vulnerable) login page
    # Target structure: http://localhost/login.php
    
    test_login_url = "http://localhost/dvwa/login.php" # Replace with your actual login URL
    test_username_field = "username"                   # Replace with your form's username field name
    test_password_field = "password"                   # Replace with your form's password field name
    test_username = "admin"                            # A valid username for login
    test_password = "password"                         # The password for that username
    test_cookie_name = "PHPSESSID"                     # The name of the session cookie

    print(f"\n--- Scanning for Predictable Session IDs: {test_login_url} ---")
    found_vulnerabilities = scanner.scan(
        scan_type="predictable_session_ids",
        login_url=test_login_url,
        username_field=test_username_field,
        password_field=test_password_field,
        username=test_username,
        password=test_password,
        num_attempts=5, # Try multiple logins to capture IDs
        cookie_name=test_cookie_name
    )
    
    if found_vulnerabilities:
        print("\n--- Session Attack Scan Results (Predictable Session IDs) ---")
        for vuln in found_vulnerabilities:
            print(f"  Vulnerability: {vuln['vulnerability']}")
            print(f"  URL: {vuln['url']}")
            print(f"  Details: {vuln['details']}")
            print("-" * 30)
    else:
        print("\nNo obvious predictable session ID vulnerabilities detected for the test endpoint.")