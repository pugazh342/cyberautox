# modules/auth_testing/scanner.py
import requests
import os
from bs4 import BeautifulSoup
from core.utils.logger import CyberLogger
from pathlib import Path # Import Path for robust path handling

class AuthTester:
    def __init__(self):
        self.logger = CyberLogger()
        self.session = requests.Session() # Use a session to maintain cookies
        
        # Determine the project root dynamically for robust path resolution
        # This assumes the script is within CyberAutoX/modules/auth_testing/
        project_root = Path(__file__).resolve().parent.parent.parent 

        self.usernames_file = project_root / "resources" / "wordlists" / "usernames.txt"
        self.passwords_file = project_root / "resources" / "wordlists" / "passwords.txt"
        
        self.usernames = self._load_wordlist(self.usernames_file)
        self.passwords = self._load_wordlist(self.passwords_file)
        # Add common login success/failure indicators (can be expanded)
        self.success_indicators = ["Welcome", "Dashboard", "Logout", "My Account"]
        self.failure_indicators = ["Invalid credentials", "Incorrect username or password", "Login failed"]

    def _load_wordlist(self, filepath): # filepath is now a Path object, which is better
        """Loads items (usernames or passwords) from a specified file."""
        items = []
        try:
            # Use filepath directly (it's already a Path object)
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    item = line.strip()
                    if item and not item.startswith('#'):
                        items.append(item)
            self.logger.info(f"Loaded {len(items)} items from {filepath}")
        except FileNotFoundError:
            self.logger.error(f"Wordlist file not found: {filepath}. Please ensure it exists.")
        except Exception as e:
            self.logger.error(f"Error loading wordlist from {filepath}: {e}")
        return items

    def _get_form_details(self, url):
        """Fetches the page and extracts login form details (action, method, input names)."""
        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            # Look for forms that might be login forms (heuristics)
            # This is a basic heuristic; a more robust solution might use form IDs or specific input types
            for form_tag in soup.find_all('form'):
                form_html = str(form_tag)
                if any(field in form_html for field in ['username', 'user', 'login', 'email', 'pass', 'password']):
                    action = form_tag.get('action', url) # Use current URL if action is relative or missing
                    method = form_tag.get('method', 'post').lower() # Default to post for login forms
                    inputs = {}
                    for input_tag in form_tag.find_all(['input', 'textarea', 'select']):
                        name = input_tag.get('name')
                        if name:
                            inputs[name] = input_tag.get('value', '')
                    self.logger.debug(f"Identified potential login form with action: {action}, method: {method}, inputs: {inputs}")
                    return action, method, inputs
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to fetch {url} or extract form details: {e}")
        return None, None, None

    def _check_login_status(self, response_text):
        """Checks the response text for login success or failure indicators."""
        response_lower = response_text.lower()
        for indicator in self.success_indicators:
            if indicator.lower() in response_lower:
                return "success"
        for indicator in self.failure_indicators:
            if indicator.lower() in response_lower:
                return "failure"
        return "unknown" # Could be due to redirect, or no clear message

    def scan(self, target_url, username_field="username", password_field="password", submit_field=None):
        """
        Performs authentication testing (brute-force) on a login form.
        :param target_url: The URL of the login page.
        :param username_field: The 'name' attribute of the username input field.
        :param password_field: The 'name' attribute of the password input field.
        :param submit_field: The 'name' attribute of the submit button (optional, for some forms).
        :return: A list of dicts, each representing a found valid credential.
        """
        self.logger.info(f"Starting Authentication Testing for: {target_url}")
        valid_credentials = []

        if not self.usernames or not self.passwords:
            self.logger.error("Username or password wordlists are empty. Aborting scan.")
            return []

        form_action, form_method, form_inputs = self._get_form_details(target_url)

        if not form_action:
            self.logger.error(f"Could not find a clear login form on {target_url}. Please ensure the URL points to a login page.")
            return []
        
        self.logger.info(f"Attempting brute-force with {len(self.usernames)} usernames and {len(self.passwords)} passwords.")

        for username in self.usernames:
            for password in self.passwords:
                data = form_inputs.copy()
                data[username_field] = username
                data[password_field] = password
                if submit_field:
                    data[submit_field] = "Submit" # Or whatever value the submit button has

                self.logger.debug(f"Trying {username}:{password}")
                
                try:
                    if form_method == 'post':
                        response = self.session.post(form_action, data=data, timeout=10)
                    else: # Assuming GET
                        response = self.session.get(form_action, params=data, timeout=10)
                    
                    login_status = self._check_login_status(response.text)

                    if login_status == "success" or ("Set-Cookie" in response.headers and "session" in response.headers["Set-Cookie"].lower()):
                        self.logger.success(f"Valid credentials found: {username}:{password} for {target_url}")
                        valid_credentials.append({
                            "vulnerability": "Weak/Default Credentials",
                            "url": target_url,
                            "username": username,
                            "password": password,
                            "response_status": response.status_code,
                            "details": "Successfully authenticated with provided credentials.",
                            "response_snippet": response.text[:200] + "..." if len(response.text) > 200 else response.text
                        })
                        # Optional: break after first valid credential found, or continue for more
                        # return valid_credentials 
                    elif login_status == "failure":
                        self.logger.info(f"Login failed for {username}:{password}")
                    else: # Unknown status, might be a redirect or different response
                        self.logger.debug(f"Login for {username}:{password} returned status {response.status_code}. Checking redirects.")
                        # Check if successful redirect implies success
                        if response.history and response.url != target_url and response.status_code == 200:
                            self.logger.success(f"Valid credentials found (via redirect): {username}:{password} for {target_url}")
                            valid_credentials.append({
                                "vulnerability": "Weak/Default Credentials",
                                "url": target_url,
                                "username": username,
                                "password": password,
                                "response_status": response.status_code,
                                "details": "Successfully authenticated and redirected.",
                                "response_snippet": response.text[:200] + "..." if len(response.text) > 200 else response.text
                            })
                except requests.exceptions.RequestException as e:
                    self.logger.error(f"Request error during Auth Testing for {target_url}: {e}")
                except Exception as e:
                    self.logger.error(f"An unexpected error occurred during Auth Testing: {e}")
        
        if not valid_credentials:
            self.logger.info(f"No valid credentials found for {target_url} using the provided wordlists.")
        
        return valid_credentials

# --- For direct testing of this module ---
if __name__ == '__main__':
    # Set up basic logging for standalone test
    import logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    print("--- Testing AuthTester ---")
    tester = AuthTester()

    # --- Test 1: Example Login Page (adjust to your local test environment) ---
    # To properly test AuthTester, you'd need:
    # 1. A web application with a login form.
    # 2. Known weak/default credentials in your wordlists that actually work on the target.

    # Example for DVWA Login Page:
    # Set DVWA Security to Low for easier testing (no token, no CAPTCHA)
    test_login_url = "http://localhost/login.php" 
    # Default DVWA fields: username="username", password="password"

    print(f"\n--- Scanning Login Page: {test_login_url} ---")
    
    # Note: If running this directly without a truly vulnerable target, it will likely report "No valid credentials found."
    # For a quick manual check of the scanner's logic flow, you can run this block.
    # The vulnerability will only be reported if a successful login indicator is found.

    found_credentials = tester.scan(test_login_url, username_field="username", password_field="password", submit_field="Login")
    
    if found_credentials:
        print("\n--- Authentication Test Results ---")
        for cred in found_credentials:
            print(f"  Vulnerability: {cred['vulnerability']}")
            print(f"  URL: {cred['url']}")
            print(f"  Valid Credential: {cred['username']}:{cred['password']}")
            print(f"  Details: {cred['details']}")
            print(f"  Response Status: {cred['response_status']}")
            print(f"  Response Snippet: {cred['response_snippet']}")
            print("-" * 30)
    else:
        print("\nNo weak/default credentials detected for the test URL.")