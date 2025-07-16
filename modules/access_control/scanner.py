# modules/access_control/scanner.py
import requests
from urllib.parse import urlparse, urljoin
from core.utils.logger import CyberLogger

class AccessControlScanner:
    def __init__(self):
        self.logger = CyberLogger()
        self.session = requests.Session() # Use a session to maintain cookies/auth
        self.success_statuses = [200, 201, 204]
        self.unauthorized_statuses = [401, 403] # Common unauthorized responses

    def _make_request(self, url, method="GET", headers=None, data=None, json_data=None, cookies=None):
        """Helper to make HTTP requests."""
        try:
            if method.upper() == "POST":
                response = self.session.post(url, headers=headers, data=data, json=json_data, cookies=cookies, timeout=10)
            elif method.upper() == "PUT":
                response = self.session.put(url, headers=headers, data=data, json=json_data, cookies=cookies, timeout=10)
            elif method.upper() == "DELETE":
                response = self.session.delete(url, headers=headers, cookies=cookies, timeout=10)
            else: # Default to GET
                response = self.session.get(url, headers=headers, cookies=cookies, timeout=10)
            
            return response
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Access Control request failed for {url} ({method}): {e}")
            return None

    def test_horizontal_escalation(self, 
                                   vulnerable_url_pattern, 
                                   valid_user_cookies, 
                                   target_user_id="2", # The ID of the user whose data we try to access
                                   current_user_id="1", # The ID of the currently authenticated user
                                   expected_success_status=200,
                                   expected_failure_status=403):
        """
        Tests for Horizontal Privilege Escalation (accessing another user's data).
        
        :param vulnerable_url_pattern: URL pattern with a placeholder for the target user ID (e.g., "http://example.com/profile/{}").
        :param valid_user_cookies: Cookies for an authenticated user (e.g., user '1').
        :param target_user_id: The ID of the user whose data we're trying to access illicitly.
        :param current_user_id: The ID of the user whose cookies are being used for the test.
        :param expected_success_status: The HTTP status code expected for successful (legitimate) access.
        :param expected_failure_status: The HTTP status code expected for unauthorized access.
        :return: A list of dicts, each representing a found Horizontal Privilege Escalation vulnerability.
        """
        self.logger.info(f"Starting Horizontal Privilege Escalation test for: {vulnerable_url_pattern}")
        vulnerabilities = []

        if not valid_user_cookies:
            self.logger.warning("No valid user cookies provided. Cannot test horizontal escalation accurately.")
            return []

        # Step 1: Verify legitimate access (optional but good for baseline)
        current_user_url = vulnerable_url_pattern.format(current_user_id)
        self.logger.info(f"Testing legitimate access for current user ({current_user_id}): {current_user_url}")
        current_user_response = self._make_request(current_user_url, cookies=valid_user_cookies)

        if current_user_response is None or current_user_response.status_code != expected_success_status:
            self.logger.warning(f"Failed to access current user's own data ({current_user_id}). Status: {current_user_response.status_code if current_user_response else 'N/A'}. Cannot proceed with reliable horizontal escalation test.")
            return []
        self.logger.info(f"Current user data for ID {current_user_id} is accessible (Status: {current_user_response.status_code}).")

        # Step 2: Attempt to access another user's data with current user's privileges
        target_url = vulnerable_url_pattern.format(target_user_id)
        self.logger.info(f"Attempting to access target user's data ({target_user_id}) using current user's session: {target_url}")
        
        target_user_response = self._make_request(target_url, cookies=valid_user_cookies)

        if target_user_response is None:
            self.logger.error(f"No response when attempting to access {target_url}.")
            return []

        if target_user_response.status_code == expected_success_status:
            # If the current user can access another user's data, it's a vulnerability
            self.logger.success(f"Potential Horizontal Privilege Escalation: User '{current_user_id}' successfully accessed data for user '{target_user_id}' at {target_url} (Status: {target_user_response.status_code}).")
            vulnerabilities.append({
                "vulnerability": "Horizontal Privilege Escalation",
                "url": target_url,
                "method": "GET",
                "attempted_id": target_user_id,
                "details": f"User '{current_user_id}' was able to access data of user '{target_user_id}'. Response status: {target_user_response.status_code}.",
                "response_snippet": target_user_response.text[:200] + "..." if len(target_user_response.text) > 200 else target_user_response.text
            })
        elif target_user_response.status_code == expected_failure_status:
            self.logger.info(f"Access to user '{target_user_id}' data denied as expected (Status: {target_user_response.status_code}). Protected.")
        else:
            self.logger.info(f"Access to user '{target_user_id}' data returned unexpected status: {target_user_response.status_code}. Further investigation needed.")

        if not vulnerabilities:
            self.logger.info(f"No Horizontal Privilege Escalation vulnerabilities found for {vulnerable_url_pattern}.")
        
        return vulnerabilities

    def scan(self, scan_type="horizontal_escalation", **kwargs):
        """
        Main entry point for Access Control scans.
        :param scan_type: Type of access control scan to perform (e.g., "horizontal_escalation").
        :param kwargs: Arguments specific to the scan type.
        """
        if scan_type == "horizontal_escalation":
            return self.test_horizontal_escalation(**kwargs)
        else:
            self.logger.error(f"Unknown Access Control scan type: {scan_type}")
            return []


# --- For direct testing of this module ---
if __name__ == '__main__':
    # Set up basic logging for standalone test
    import logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    print("--- Testing AccessControlScanner ---")
    scanner = AccessControlScanner()

    # --- Test 1: Example Horizontal Privilege Escalation Scan ---
    # To properly test this, you'd need:
    # 1. A web application where users can access their own profile/data using an ID in the URL.
    # 2. The application should fail to properly restrict access to other users' data when a valid session is used.
    
    # Example: A (hypothetically vulnerable) user profile endpoint
    # Target structure: http://localhost:PORT/users/profile/{}
    
    # IMPORTANT: For this to work, you need valid cookies for an authenticated user.
    # You would typically obtain these by logging in through the application.
    
    # Example cookies (REPLACE WITH REAL COOKIES FROM YOUR BROWSER/BURP)
    # For DVWA's 'User ID' feature, if you log in as 'admin', your cookie might contain 'PHPSESSID' and 'security'
    # And then you might access http://localhost/vulnerabilities/fi/?page=user-info.php&user_id=1
    # You'd need to adapt the URL pattern and provide actual cookies.
    
    test_cookies = {
        "PHPSESSID": "YOUR_SESSION_ID_HERE",  # Replace with a real session ID
        "security": "low"                     # Example from DVWA
    }

    # Replace with your actual vulnerable URL pattern and user IDs for testing
    vulnerable_url = "http://localhost/vulnerabilities/fi/?page=user-info.php&user_id={}"
    
    # User '1' is the one whose cookies you have. User '2' is another user you try to access.
    current_user = "1"
    target_user = "2"
    
    print(f"\n--- Scanning for Horizontal Escalation: {vulnerable_url} ---")
    found_vulnerabilities = scanner.scan(
        scan_type="horizontal_escalation",
        vulnerable_url_pattern=vulnerable_url,
        valid_user_cookies=test_cookies,
        current_user_id=current_user,
        target_user_id=target_user,
        expected_success_status=200,
        expected_failure_status=403 # Or 401, depending on the app's response
    )
    
    if found_vulnerabilities:
        print("\n--- Access Control Scan Results (Horizontal Escalation) ---")
        for vuln in found_vulnerabilities:
            print(f"  Vulnerability: {vuln['vulnerability']}")
            print(f"  URL: {vuln['url']}")
            print(f"  Attempted ID: {vuln['attempted_id']}")
            print(f"  Details: {vuln['details']}")
            print(f"  Response Snippet: {vuln['response_snippet']}")
            print("-" * 30)
    else:
        print("\nNo Horizontal Privilege Escalation vulnerabilities detected for the test endpoint.")