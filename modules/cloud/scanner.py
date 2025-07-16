# modules/cloud/scanner.py
from core.utils.logger import CyberLogger
import requests # Used for simulated web requests to check public access

class CloudAuditor:
    def __init__(self):
        self.logger = CyberLogger()
        self.vulnerabilities = []

    def check_public_bucket_access(self, bucket_url, expected_public_content_keyword=None):
        """
        Simulates checking if a cloud storage bucket (like S3) is publicly accessible.
        In a real scenario, this would use cloud provider SDKs to check ACLs, bucket policies.

        :param bucket_url: The URL of the bucket (e.g., 'http://bucket-name.s3.amazonaws.com/').
        :param expected_public_content_keyword: A keyword to look for if a successful public access is found.
        :return: List of findings if publicly exposed.
        """
        self.logger.info(f"Attempting to check public access for bucket: {bucket_url}")
        findings = []

        try:
            # Simulate an HTTP GET request to the bucket URL
            # In a real tool, we might try listing objects or checking for a known public file.
            response = requests.get(bucket_url, timeout=5)

            if response.status_code == 200:
                is_public = False
                details = f"Bucket responded with 200 OK. Content length: {len(response.content)} bytes."

                if expected_public_content_keyword:
                    if expected_public_content_keyword in response.text:
                        is_public = True
                        details += f" Found expected keyword '{expected_public_content_keyword}' in response."
                        self.logger.success(f"Bucket {bucket_url} is publicly accessible and contains '{expected_public_content_keyword}'!")
                    else:
                        # If a keyword was expected but not found, don't flag as public for this check.
                        self.logger.info(f"Bucket {bucket_url} responded 200 OK, but did not contain expected keyword. Not flagged as public based on keyword check.")
                else:
                    # If no specific keyword is provided, a 200 OK indicates some level of public access for demo.
                    # A real scanner would analyze bucket listings or specific object access.
                    is_public = True
                    self.logger.success(f"Bucket {bucket_url} is publicly accessible (200 OK, no specific content keyword required).")
                
                if is_public: # Only add finding if explicitly determined to be public
                    finding = {
                        "vulnerability": "Publicly Accessible Cloud Storage Bucket",
                        "details": details,
                        "severity": "High",
                        "location": bucket_url,
                        "response_status": response.status_code
                    }
                    self.vulnerabilities.append(finding)
                    findings.append(finding)
            elif response.status_code in [403, 404, 301]:
                self.logger.info(f"Bucket {bucket_url} responded with {response.status_code} (likely not publicly accessible or does not exist).")
            else:
                self.logger.warning(f"Bucket {bucket_url} responded with unexpected status code: {response.status_code}")

        except requests.exceptions.ConnectionError:
            self.logger.error(f"Could not connect to bucket URL: {bucket_url}. It might not exist or is not publicly resolvable.")
        except requests.exceptions.Timeout:
            self.logger.error(f"Connection to bucket URL timed out: {bucket_url}.")
        except Exception as e:
            self.logger.error(f"An error occurred while checking {bucket_url}: {e}")
        
        return findings

    def scan(self, scan_type="public_bucket_access", **kwargs):
        """
        Main entry point for cloud security scans.

        :param scan_type: Type of cloud scan to perform (e.g., "public_bucket_access").
        :param kwargs: Arguments specific to the scan type.
                       For "public_bucket_access": 'bucket_url', 'expected_public_content_keyword'.
        """
        self.vulnerabilities = [] # Reset for each scan call

        if scan_type == "public_bucket_access":
            bucket_url = kwargs.get('bucket_url')
            if not bucket_url:
                self.logger.error("Missing 'bucket_url' for public_bucket_access scan type.")
                return []
            
            expected_keyword = kwargs.get('expected_public_content_keyword')
            self.check_public_bucket_access(bucket_url, expected_keyword)
        
        # Add more scan types here (e.g., 'iam_policy_misconfig', 'exposed_compute_instance')
        # In a real tool:
        # if scan_type == "iam_policy_misconfig":
        #    aws_profile = kwargs.get('aws_profile')
        #    self.check_iam_policies(aws_profile)
        # elif scan_type == "exposed_compute_instance":
        #    instance_ip = kwargs.get('instance_ip')
        #    self.check_compute_instance_exposure(instance_ip)
        
        if not self.vulnerabilities:
            self.logger.info(f"No cloud vulnerabilities detected for scan type: {scan_type}")
        
        return self.vulnerabilities

# --- For direct testing of this module ---
if __name__ == '__main__':
    # Set up basic logging for standalone test
    import logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    print("--- Testing CloudAuditor ---")
    auditor = CloudAuditor()

    # --- Test 1: Simulate a publicly accessible bucket ---
    # Using a known public test URL for demonstration that returns 200 OK
    # By default, a 200 OK will now be flagged as public if no keyword is specified.
    print("\n--- Test Case 1: Simulated Public Bucket (Success) ---")
    public_test_url = "http://httpbin.org/status/200" # Returns 200 OK
    results_public = auditor.scan(
        scan_type="public_bucket_access",
        bucket_url=public_test_url
        # Removed expected_public_content_keyword so 200 OK is sufficient for a finding
    )
    if results_public:
        print("\nCloud Vulnerabilities Found (Test 1):")
        for vuln in results_public:
            print(f"  - {vuln['vulnerability']}: {vuln['details']}")
    else:
        print("\nNo cloud vulnerabilities found for Test Case 1 (unexpected if httpbin.org is reachable).")

    # --- Test 2: Simulate a non-public/non-existent bucket ---
    print("\n--- Test Case 2: Simulated Non-Public/Non-Existent Bucket (Failure) ---")
    non_public_test_url = "http://nonexistent-bucket-12345.s3.amazonaws.com/" # Will likely result in ConnectionError or 404
    results_non_public = auditor.scan(
        scan_type="public_bucket_access",
        bucket_url=non_public_test_url
    )
    if results_non_public:
        print("\nCloud Vulnerabilities Found (Test 2):")
        for vuln in results_non_public:
            print(f"  - {vuln['vulnerability']}: {vuln['details']}")
    else:
        print("\nNo cloud vulnerabilities found for Test Case 2 (as expected).")

    # --- Test 3: Simulate a publicly accessible bucket with specific content keyword ---
    print("\n--- Test Case 3: Public Bucket with Specific Content Keyword ---")
    # Using a page that actually contains content, e.g., Google's homepage
    # You might need to change the keyword if Google changes its homepage content.
    google_url = "https://www.google.com"
    results_google = auditor.scan(
        scan_type="public_bucket_access",
        bucket_url=google_url,
        expected_public_content_keyword="Google" # Expected keyword on Google homepage
    )
    if results_google:
        print("\nCloud Vulnerabilities Found (Test 3):")
        for vuln in results_google:
            print(f"  - {vuln['vulnerability']}: {vuln['details']}")
    else:
        print("\nNo cloud vulnerabilities found for Test Case 3 (unexpected if Google is reachable and contains 'Google').")