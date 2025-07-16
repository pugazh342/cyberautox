# modules/ssrf_fileupload/scanner.py
import requests
from core.utils.logger import CyberLogger
import mimetypes
import os

class SSRFFileUploader:
    def __init__(self):
        self.logger = CyberLogger()
        self.session = requests.Session()
        self.success_statuses = [200, 201, 204]
        self.ssrf_detection_keywords = ["127.0.0.1", "localhost", "internal-ip", "private-ip", "metadata.google.internal"] # Keywords to look for in response if SSRF allows displaying content

    def _make_request(self, url, method="GET", headers=None, data=None, files=None, json_data=None, cookies=None, allow_redirects=True):
        """Helper to make HTTP requests."""
        try:
            response = self.session.request(method.upper(), url, headers=headers, data=data, files=files, json=json_data, cookies=cookies, allow_redirects=allow_redirects, timeout=15)
            return response
        except requests.exceptions.RequestException as e:
            self.logger.error(f"SSRF/File Upload request failed for {url} ({method}): {e}")
            return None

    def test_ssrf_via_upload(self, 
                             upload_url, 
                             file_field_name, 
                             ssrf_payload_url="http://127.0.0.1/nonexistent", 
                             filename="test_ssrf.jpg", 
                             mime_type="image/jpeg",
                             additional_form_data=None, # e.g., {'csrf_token': 'abc'}
                             expected_ssrf_success_keyword=None): # e.g., part of the internal page or error
        """
        Tests for SSRF vulnerabilities via a file upload mechanism.
        This attempts to upload a file (e.g., an image) that tries to fetch content
        from an internal or controlled external URL, and then analyzes the response.

        The vulnerability often lies in image processing libraries that fetch external
        content (e.g., resizing an image from a URL, or processing EXIF data that points to a URL).

        :param upload_url: The URL of the file upload endpoint.
        :param file_field_name: The name of the file input field in the HTML form (e.g., 'file', 'image').
        :param ssrf_payload_url: The URL the server should fetch internally if vulnerable (e.g., 'http://127.0.0.1/').
        :param filename: The name to give the uploaded file (e.g., 'image.jpg').
        :param mime_type: The MIME type of the uploaded file (e.g., 'image/jpeg', 'application/xml').
        :param additional_form_data: A dictionary of other form fields (e.g., CSRF tokens).
        :param expected_ssrf_success_keyword: A keyword expected in the response if the SSRF payload was processed.
        :return: A list of dicts, each representing a found SSRF vulnerability.
        """
        self.logger.info(f"Testing for SSRF via file upload on {upload_url} with payload URL: {ssrf_payload_url}")
        vulnerabilities = []

        # Create a dummy file-like object or a string for the "image" content
        # For SSRF, the "image" content might itself contain the URL to be fetched
        # For example, an SVG that tries to load external content, or a crafted EXIF header in a JPEG.
        # This example uses a simplified approach: we're assuming a processing library
        # might fetch a remote resource based on some metadata or content of the file.
        # A more sophisticated test would involve crafting specific image formats (SVG, EXIF, etc.)

        # Simple case: Assume the server fetches a URL from within the file or from a parameter.
        # This initial version focuses on if the server attempts to process a URL within a dummy file.
        # Real-world SSRF via upload requires careful crafting of specific file types (e.g., SVG, PDF, images with EXIF).
        
        # Craft a basic "file" content. This will need to be adapted heavily
        # based on the specific vulnerability being targeted (e.g., ImageMagick SSRF).
        # For a general "SSRF via upload", we are mainly looking for evidence that
        # the server attempted to connect to `ssrf_payload_url`. This is hard to confirm
        # solely from the upload response without out-of-band interaction (e.g., a listener).
        # For this basic implementation, we'll check if any 'internal' keywords
        # accidentally leak in the response or if the status code changes unexpectedly.
        
        # Crafting a very basic "image" that might trick some parsers (highly dependent on server)
        # This is not a universal SSRF payload, but a placeholder for a crafted file.
        # A true SSRF payload would be a malformed JPEG/SVG/PDF with external entity/xlink references.
        # Here, we're just providing a dummy binary blob.
        dummy_file_content = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\x0cIDATx\xda\xed\xc1\x01\x01\x00\x00\x00\xc2\xa0\xf7Om\x00\x00\x00\x00IEND\xaeB`\x82"
        # Add a "comment" that *might* be processed as a URL by some parsers/libraries
        # This is highly speculative for a generic file upload.
        # For practical SSRF via upload, you'd be crafting specific file types.
        # Example: SVG with <image xlink:href="http://127.0.0.1/"/>
        # Or an image with crafted EXIF data pointing to a URL.
        # For simplicity, we'll try to put the URL in the content, hoping for a very naive parser.
        # A more realistic test would involve a controlled external server (Burp Collaborator, interact.sh)
        # to confirm if the internal server makes an out-of-band request.
        crafted_file_content = dummy_file_content + f"\n".encode()

        files = {file_field_name: (filename, crafted_file_content, mime_type)}
        
        # Combine additional form data if provided
        data_to_send = additional_form_data if additional_form_data else {}

        self.logger.info(f"Uploading file '{filename}' to {upload_url} for SSRF test...")
        response = self._make_request(upload_url, method="POST", files=files, data=data_to_send)

        if response is None:
            self.logger.warning(f"No response received from {upload_url} for SSRF upload test.")
            return []

        # Analyze the response
        ssrf_detected = False
        details = f"Response Status: {response.status_code}. Response Size: {len(response.text)} bytes."

        # Check for keywords that might indicate successful SSRF
        response_text_lower = response.text.lower()
        if expected_ssrf_success_keyword and expected_ssrf_success_keyword.lower() in response_text_lower:
            ssrf_detected = True
            details += f" Found expected keyword '{expected_ssrf_success_keyword}' in response."
        else:
            for keyword in self.ssrf_detection_keywords:
                if keyword.lower() in response_text_lower:
                    ssrf_detected = True
                    details += f" Found internal keyword '{keyword}' in response (Possible SSRF or info leak)."
                    break
        
        # Check if the upload itself was successful, indicating the server processed it
        if response.status_code in self.success_statuses:
            self.logger.info(f"File upload successful (Status: {response.status_code}). Now analyzing for SSRF indications...")
            if ssrf_detected:
                self.logger.success(f"Potential SSRF via File Upload vulnerability detected on {upload_url}!")
                vulnerabilities.append({
                    "vulnerability": "SSRF via File Upload",
                    "url": upload_url,
                    "details": details,
                    "ssrf_payload_url": ssrf_payload_url,
                    "response_snippet": response.text[:500]
                })
            else:
                self.logger.info(f"File upload successful, but no direct SSRF indicators found in response for {upload_url}. (Status: {response.status_code})")
        else:
            self.logger.warning(f"File upload to {upload_url} failed or returned unexpected status: {response.status_code}. (Response: {response.text[:500]})")
            # If upload fails, SSRF test cannot proceed reliably
            
        if not vulnerabilities:
            self.logger.info(f"No SSRF via File Upload vulnerabilities detected for {upload_url}.")

        return vulnerabilities
    
    def scan(self, scan_type="ssrf_via_upload", **kwargs):
        """
        Main entry point for SSRF/File Upload scans.
        :param scan_type: Type of scan to perform (e.g., "ssrf_via_upload").
        :param kwargs: Arguments specific to the scan type.
        """
        if scan_type == "ssrf_via_upload":
            return self.test_ssrf_via_upload(**kwargs)
        else:
            self.logger.error(f"Unknown SSRF/File Upload scan type: {scan_type}")
            return []

# --- For direct testing of this module ---
if __name__ == '__main__':
    # Set up basic logging for standalone test
    import logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    print("--- Testing SSRFFileUploader ---")
    scanner = SSRFFileUploader()

    # --- Test 1: Example SSRF via File Upload Scan ---
    # To properly test this, you'd need:
    # 1. A web application with a file upload vulnerability that processes uploaded content.
    # 2. The processing library must be vulnerable to SSRF (e.g., by fetching external URLs from metadata or file content).
    # 3. The server must disclose some information (e.g., error messages, internal content) in the response,
    #    or you need an out-of-band detection mechanism (e.g., a controlled listener).
    
    # Example: A (hypothetically vulnerable) image upload page
    test_upload_url = "http://localhost/upload_image.php" # Replace with your actual file upload URL
    test_file_field_name = "image"                      # Replace with the name of the file input field

    # This URL is what the vulnerable server would try to fetch internally
    # For a true test, this would often be an IP like 169.254.169.254 (AWS metadata) or a controlled external listener.
    test_ssrf_payload_url = "http://127.0.0.1/admin_dashboard_secret" 
    
    # Optional: A keyword you expect to see in the response if the SSRF succeeds (e.g., from an internal page's content)
    test_expected_keyword = "admin panel"

    print(f"\n--- Scanning for SSRF via File Upload on {test_upload_url} ---")
    found_vulnerabilities = scanner.scan(
        scan_type="ssrf_via_upload",
        upload_url=test_upload_url,
        file_field_name=test_file_field_name,
        ssrf_payload_url=test_ssrf_payload_url,
        filename="ssrf_test.png",
        mime_type="image/png",
        expected_ssrf_success_keyword=test_expected_keyword
    )
    
    if found_vulnerabilities:
        print("\n--- SSRF via File Upload Scan Results ---")
        for vuln in found_vulnerabilities:
            print(f"  Vulnerability: {vuln['vulnerability']}")
            print(f"  URL: {vuln['url']}")
            print(f"  Details: {vuln['details']}")
            print(f"  SSRF Payload URL: {vuln['ssrf_payload_url']}")
            print(f"  Response Snippet: {vuln['response_snippet']}")
            print("-" * 30)
    else:
        print("\nNo SSRF via File Upload vulnerabilities detected for the test endpoint.")