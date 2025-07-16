# modules/waf_bypass/waf_detect.py
import requests
from core.utils.logger import CyberLogger # Import CyberLogger

class WAFDetector:
    WAF_SIGNATURES = {
        'Cloudflare': 'cloudflare',
        'Akamai': 'akamai',
        'Incapsula': 'incapsula', # Added common WAF for example
        'ModSecurity': 'mod_security',
        'Sucuri': 'sucuri/cloudproxy' # Added common WAF for example
    }

    def __init__(self):
        self.logger = CyberLogger() # Initialize logger

    def detect(self, target_url):
        self.logger.info(f"Attempting to detect WAF for: {target_url}")
        detected = []
        try:
            resp = requests.get(target_url, timeout=5) # Added timeout
            
            # Check common WAF headers and server banners
            headers = {k.lower(): v.lower() for k, v in resp.headers.items()}

            # Check specific headers
            if 'server' in headers and any(sig in headers['server'] for sig in ['cloudflare', 'sucuri', 'akamai']):
                for waf_name, sig in self.WAF_SIGNATURES.items():
                    if sig in headers['server']:
                        detected.append(waf_name)
            
            if 'x-cache' in headers and 'cloudflare' in headers['x-cache']:
                if 'Cloudflare' not in detected: detected.append('Cloudflare')
            if 'cf-ray' in headers:
                if 'Cloudflare' not in detected: detected.append('Cloudflare')
            if 'x-sucuri-id' in headers:
                if 'Sucuri' not in detected: detected.append('Sucuri')
            if 'x-incapsula-request-id' in headers:
                if 'Incapsula' not in detected: detected.append('Incapsula')
            
            # Additional heuristic: checking status code for common WAF block page
            if resp.status_code == 999: # Common for Akamai
                if 'Akamai' not in detected: detected.append('Akamai')
            
            # Generic WAF detection (less reliable but can catch others)
            # This is a very basic example; real WAF detection is complex
            if resp.status_code >= 400 and resp.status_code != 404:
                if any(waf in resp.text.lower() for waf in ['cloudflare', 'sucuri', 'incapsula', 'mod_security']):
                    for waf_name, sig in self.WAF_SIGNATURES.items():
                        if sig in resp.text.lower() and waf_name not in detected:
                            detected.append(waf_name)
            
            if detected:
                self.logger.info(f"Detected WAF(s): {', '.join(detected)}")
                return detected
            else:
                self.logger.info("No common WAF signatures detected.")
                return ["No WAF detected"]

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error during WAF detection for {target_url}: {e}")
            return [f"Error: {e}"]
        except Exception as e:
            self.logger.error(f"An unexpected error occurred during WAF detection: {e}")
            return [f"Error: {e}"]