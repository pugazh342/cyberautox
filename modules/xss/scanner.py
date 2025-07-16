# modules/xss/scanner.py
import requests
from pathlib import Path
from core.utils.logger import CyberLogger
from core.engines.web_crawler import WebCrawler
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from bs4 import BeautifulSoup # Ensure this is imported

class XSSScanner:
    def __init__(self, target_url):
        self.target = target_url
        self.logger = CyberLogger()
        self.payloads = self._load_payloads()
        self.crawler = WebCrawler(target_url)
        self.found_vulnerabilities = []

    def _load_payloads(self):
        payload_file = Path("resources/payloads/xss.txt")
        if not payload_file.exists():
            self.logger.error("XSS payloads not found! Create 'resources/payloads/xss.txt'")
            return []
        with open(payload_file) as f:
            return [line.strip() for line in f if line.strip()]

    def _test_url_for_xss(self, original_url, parameter, original_value, payload):
        """
        Attempts to inject an XSS payload and checks for its reflection in executable contexts.
        """
        parsed_url = urlparse(original_url)
        query_params = parse_qs(parsed_url.query)

        modified_params = query_params.copy()
        modified_params[parameter] = payload # Inject payload

        new_query = urlencode(modified_params, doseq=True)
        test_url = urlunparse(
            (parsed_url.scheme, parsed_url.netloc, parsed_url.path,
             parsed_url.params, new_query, parsed_url.fragment)
        )

        try:
            self.logger.debug(f"Testing {test_url} for XSS in param '{parameter}' with payload: {payload[:50]}...")
            response = requests.get(test_url, timeout=7) # Increased timeout slightly
            response.raise_for_status()

            # Analyze the response with BeautifulSoup for reflection in executable contexts
            soup = BeautifulSoup(response.text, 'html.parser')

            # 1. Check for reflection inside <script> tags
            for script_tag in soup.find_all('script'):
                if script_tag.string and payload in script_tag.string:
                    self.logger.warning(f"XSS found in <script> tag at: {original_url} (Param: '{parameter}') with payload: {payload}")
                    self.found_vulnerabilities.append({
                        "url": original_url,
                        "parameter": parameter,
                        "payload": payload,
                        "reflected_url": test_url,
                        "location": "Inside <script> tag",
                        "detection_method": "String reflection"
                    })
                    return True # Vulnerability found

            # 2. Check for reflection in HTML attributes (e.g., onerror, onload, src, href)
            # This is simplified; real-world requires checking many attributes.
            for tag in soup.find_all(True): # Find all HTML tags
                for attr, value in tag.attrs.items():
                    if isinstance(value, str) and payload in value:
                        # Check for common event handlers or vulnerable attributes
                        if attr.lower() in ['onload', 'onerror', 'onclick', 'onmouseover',
                                            'src', 'href', 'background', 'style', 'data']:
                            # Additional check: Does the attribute value look like executable code?
                            # This is still basic; a real check would involve parsing JS.
                            if any(js_keyword in payload.lower() for js_keyword in ['alert', 'prompt', 'confirm', 'javascript:']):
                                self.logger.warning(f"XSS found in attribute '{attr}' of <{tag.name}> tag at: {original_url} (Param: '{parameter}') with payload: {payload}")
                                self.found_vulnerabilities.append({
                                    "url": original_url,
                                    "parameter": parameter,
                                    "payload": payload,
                                    "reflected_url": test_url,
                                    "location": f"In {tag.name} tag's '{attr}' attribute",
                                    "detection_method": "Attribute reflection"
                                })
                                return True # Vulnerability found

            # 3. Basic body reflection (as a fallback, but less precise)
            if payload in response.text:
                self.logger.debug(f"Payload '{payload[:20]}...' reflected in body, but not in executable context for {original_url}")
                # You might log this as "potential" or "low confidence" if no other specific context is found.

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request error during XSS test for {test_url}: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error during XSS test for {test_url}: {e}")

        return False # No vulnerability found in this test

    def scan(self):
        self.logger.info(f"Starting XSS scan for {self.target}")
        if not self.payloads:
            self.logger.warning("No XSS payloads loaded. Skipping scan.")
            return []

        internal_urls, _ = self.crawler.crawl(max_depth=1, max_urls=20)
        self.logger.info(f"Crawler found {len(internal_urls)} internal URLs to test for XSS.")

        # Add the base target URL itself if it's not in internal_urls and has params
        if '?' in self.target and self.target not in internal_urls:
            internal_urls.insert(0, self.target) # Test the base URL first if it has parameters

        # Filter to only URLs with query parameters for now, as our _test_url_for_xss focuses on them
        urls_with_params = [url for url in internal_urls if '?' in url]

        # 2. Iterate through discovered URLs and inject payloads
        for url in urls_with_params:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)

            for param, values in query_params.items():
                for original_value in values: # Test with original value as the injection point
                    for payload in self.payloads:
                        found = self._test_url_for_xss(url, param, original_value, payload)
                        if found:
                            # If a vulnerability is found for a URL/param/payload, no need to try more payloads for this param.
                            # For comprehensive scan, you might remove this 'break'
                            break # Move to next parameter
                if found:
                    break # Move to next URL if vulnerability found in any parameter

        if self.found_vulnerabilities:
            self.logger.warning(f"XSS scan completed. Found {len(self.found_vulnerabilities)} potential XSS vulnerabilities.")
        else:
            self.logger.info("XSS scan completed. No XSS vulnerabilities found.")

        return self.found_vulnerabilities