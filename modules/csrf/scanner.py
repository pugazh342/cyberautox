# modules/csrf/scanner.py
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from core.utils.logger import CyberLogger

class CSRFScanner:
    def __init__(self):
        self.logger = CyberLogger()
        self.session = requests.Session() # Use a session to maintain cookies
        self.token_names = ['csrf_token', 'authenticity_token', '_csrf', 'token'] # Common anti-CSRF token names

    def _get_form_details(self, url, html_content):
        """Extracts details (action, method, inputs) from forms in HTML content."""
        soup = BeautifulSoup(html_content, 'html.parser')
        forms = []
        for form_tag in soup.find_all('form'):
            form_details = {}
            form_details['action'] = form_tag.get('action')
            form_details['method'] = form_tag.get('method', 'get').lower()
            form_details['inputs'] = []

            for input_tag in form_tag.find_all(['input', 'textarea', 'select']):
                input_name = input_tag.get('name')
                input_value = input_tag.get('value', '')
                input_type = input_tag.get('type', 'text') # default to text for simplicity

                if input_name:
                    form_details['inputs'].append({
                        'name': input_name,
                        'value': input_value,
                        'type': input_type
                    })
            forms.append(form_details)
        return forms

    def _extract_csrf_token(self, form_details):
        """Attempts to extract an anti-CSRF token from form inputs."""
        for input_field in form_details['inputs']:
            if input_field['type'] == 'hidden' and input_field['name'] in self.token_names:
                self.logger.debug(f"Found potential CSRF token '{input_field['name']}' with value '{input_field['value']}'")
                return input_field['name'], input_field['value']
        return None, None

    def _build_request_data(self, form_details, token_name=None, token_value=None, bypass_token=True):
        """
        Builds data payload for the request.
        If bypass_token is True, omits or modifies the token.
        """
        data = {}
        for input_field in form_details['inputs']:
            if input_field['name'] and (input_field['name'] != token_name or not bypass_token):
                data[input_field['name']] = input_field['value']
            elif input_field['name'] == token_name and not bypass_token:
                # Include the token if we are not bypassing
                data[token_name] = token_value if token_value else input_field['value']
            # If bypassing, don't add the token to 'data'
        return data

    def scan(self, target_url):
        """
        Scans a target URL for CSRF vulnerabilities.
        Fetches the page, identifies forms, and attempts to forge requests.
        :param target_url: The URL to scan (e.g., "http://example.com/profile/edit").
        :return: A list of dicts, each representing a found vulnerability.
        """
        self.logger.info(f"Starting CSRF scan for: {target_url}")
        vulnerabilities = []

        try:
            # 1. Fetch the target page to get forms and cookies
            initial_response = self.session.get(target_url, timeout=15)
            initial_response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
            
            forms = self._get_form_details(target_url, initial_response.text)

            if not forms:
                self.logger.info(f"No forms found on {target_url}. Skipping CSRF scan for this URL.")
                return []

            self.logger.info(f"Found {len(forms)} form(s) on {target_url}.")

            for i, form in enumerate(forms):
                self.logger.info(f"Analyzing Form {i+1}: Action='{form['action']}', Method='{form['method'].upper()}'")
                
                form_action_url = urljoin(target_url, form['action'])
                token_name, token_value = self._extract_csrf_token(form)
                
                # --- Test Case 1: Attempt to forge request WITHOUT CSRF token ---
                self.logger.info(f"Attempting to forge request without CSRF token for Form {i+1}...")
                forged_data = self._build_request_data(form, token_name=token_name, bypass_token=True)
                
                forged_response = None
                try:
                    if form['method'] == 'post':
                        forged_response = self.session.post(form_action_url, data=forged_data, timeout=15)
                    else: # Assuming GET for simplicity if not POST
                        forged_response = self.session.get(form_action_url, params=forged_data, timeout=15)
                    
                    # A true CSRF vulnerability is detected if the forged request
                    # without the token still successfully performs the intended action.
                    # This often means a 200 OK status, and content indicating success
                    # or absence of an error related to missing token.
                    # This is highly application-dependent and requires manual verification.
                    
                    # For automated detection, we look for signs that a token was NOT required.
                    # This is an heuristic and might have false positives/negatives.
                    if forged_response.status_code == 200:
                        if token_name and f"Invalid {token_name}" not in forged_response.text and \
                           f"Missing {token_name}" not in forged_response.text and \
                           "CSRF token mismatch" not in forged_response.text:
                            
                            self.logger.warning(f"Potential CSRF vulnerability found on Form {i+1} (Action: {form_action_url})!")
                            self.logger.warning(f"  - Request without token received 200 OK and no explicit token error.")
                            vulnerabilities.append({
                                "vulnerability": "CSRF",
                                "url": target_url,
                                "form_action": form_action_url,
                                "method": form['method'].upper(),
                                "details": "Request without CSRF token was processed successfully (heuristic detection).",
                                "response_status": forged_response.status_code,
                                "response_snippet": forged_response.text[:200] + "..." if len(forged_response.text) > 200 else forged_response.text
                            })
                        elif not token_name:
                             self.logger.warning(f"Potential CSRF vulnerability found on Form {i+1} (Action: {form_action_url}) - No CSRF token found in form and request received 200 OK.")
                             vulnerabilities.append({
                                "vulnerability": "CSRF",
                                "url": target_url,
                                "form_action": form_action_url,
                                "method": form['method'].upper(),
                                "details": "No CSRF token found in form, and request was processed successfully (heuristic detection).",
                                "response_status": forged_response.status_code,
                                "response_snippet": forged_response.text[:200] + "..." if len(forged_response.text) > 200 else forged_response.text
                            })
                    elif forged_response.status_code in [403, 419]: # Common CSRF protection codes
                        self.logger.info(f"Form {i+1} appears to be protected (Status {forged_response.status_code}).")
                    else:
                        self.logger.info(f"Form {i+1} (without token) responded with status {forged_response.status_code}.")

                except requests.exceptions.RequestException as e:
                    self.logger.error(f"Request error during CSRF test for {form_action_url}: {e}")
                except Exception as e:
                    self.logger.error(f"An unexpected error occurred during CSRF scan: {e}")

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to fetch {target_url}: {e}")
        except Exception as e:
            self.logger.error(f"An unexpected error occurred during CSRF scan: {e}")
        
        if not vulnerabilities:
            self.logger.info(f"No CSRF vulnerabilities found for {target_url}.")
        
        return vulnerabilities

# --- For direct testing of this module ---
if __name__ == '__main__':
    # Set up basic logging for standalone test
    import logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    print("--- Testing CSRFScanner ---")
    scanner = CSRFScanner()

    # --- Test 1: Example URL with a form (adjust to your local test environment) ---
    # To properly test CSRF, you'd need:
    # 1. A web application with a form (e.g., login, change password, post comment).
    # 2. To be authenticated to that application (scanner uses a session).
    # 3. An *actual* CSRF vulnerability (where the action is performed even without a token).

    # Example for a known vulnerable target (e.g., a specific DVWA CSRF challenge)
    # This example URL assumes a form that submits to /vulnerabilities/csrf/
    # You'd typically need to log in to DVWA first for CSRF to be relevant.
    test_target_url = "http://localhost/vulnerabilities/csrf/" 
    # Or a simple HTML page with a form for testing:
    # Example local HTML file for testing (if you serve it):
    # test_target_url = "http://localhost:8000/simple_form.html"
    # To serve a simple HTML: python -m http.server 8000
    # simple_form.html content:
    # <form action="/submit" method="POST">
    #   <input type="text" name="username" value="test">
    #   <input type="hidden" name="password" value="pass">
    #   <button type="submit">Submit</button>
    # </form>

    print(f"\n--- Scanning URL for CSRF: {test_target_url} ---")
    
    # NOTE: This scan will likely NOT find a vulnerability if run against a modern,
    # well-protected site or if your test server isn't intentionally vulnerable.
    # It primarily checks for the *absence* of token validation or token presence.
    
    # For a real CSRF test, you would often first perform a login POST request
    # using self.session.post() to establish the session cookies, then call scan().
    # Example (conceptual login for DVWA):
    # login_url = "http://localhost/login.php"
    # login_data = {"username": "admin", "password": "password", "Login": "Login"}
    # scanner.session.post(login_url, data=login_data) # Establish session
    # print("Attempting scan after simulated login...")
    
    found_vulnerabilities = scanner.scan(test_target_url)
    
    if found_vulnerabilities:
        print("\n--- CSRF Scan Results ---")
        for vuln in found_vulnerabilities:
            print(f"  Vulnerability: {vuln['vulnerability']}")
            print(f"  URL: {vuln['url']}")
            print(f"  Form Action: {vuln['form_action']}")
            print(f"  Method: {vuln['method']}")
            print(f"  Details: {vuln['details']}")
            print(f"  Response Status: {vuln['response_status']}")
            print(f"  Response Snippet: {vuln['response_snippet']}")
            print("-" * 30)
    else:
        print("\nNo CSRF vulnerabilities detected for the test URL.")