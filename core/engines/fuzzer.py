# core/engines/fuzzer.py
import requests
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from core.utils.logger import CyberLogger

class Fuzzer:
    def __init__(self):
        self.logger = CyberLogger()
        self.common_payloads = [
            "'", "\"", "`", "\\", ";", "--", "#", "/*", "*/", "<", ">",
            "../", "..\\", "%00", "%ff", "%0a", "%0d",
            "SLEEP(5)", "OR 1=1--", "' OR 1=1--", '" OR 1=1--'
        ]
        self.numeric_payloads = [
            "0", "-1", "1'", "1 or 1=1", "1 and 1=1", "9999999999999999"
        ]
        self.string_payloads = [
            "test", "admin", "root", "<script>alert(1)</script>"
        ]
        self.path_traversal_payloads = [
            "../", "..\\", "../../", "..\\..\\", "../../../etc/passwd", "..\\..\\..\\windows\\win.ini"
        ]

    def _generate_all_payloads(self):
        """Combines various types of payloads."""
        all_payloads = set()
        all_payloads.update(self.common_payloads)
        all_payloads.update(self.numeric_payloads)
        all_payloads.update(self.string_payloads)
        all_payloads.update(self.path_traversal_payloads)
        return list(all_payloads)

    def fuzz_url_params(self, url, params_to_fuzz=None, payloads=None):
        """
        Fuzzes URL query parameters.
        :param url: The base URL to fuzz.
        :param params_to_fuzz: A list of parameter names to fuzz. If None, all parameters will be fuzzed.
        :param payloads: A list of payloads to use. If None, common_payloads will be used.
        :return: A list of URLs that were fuzzed.
        """
        fuzzed_urls = []
        target_payloads = payloads if payloads is not None else self._generate_all_payloads()

        parsed_url = urlparse(url)
        original_query_params = parse_qs(parsed_url.query)

        if not original_query_params:
            self.logger.debug(f"URL {url} has no query parameters to fuzz.")
            return []

        params_to_operate_on = params_to_fuzz if params_to_fuzz else original_query_params.keys()

        for param_name in params_to_operate_on:
            if param_name not in original_query_params:
                continue # Skip if parameter not in original URL and not forcing new param

            original_value = original_query_params.get(param_name, [''])[0] # Get first value if multiple

            for payload in target_payloads:
                modified_params = original_query_params.copy()
                modified_params[param_name] = payload # Inject payload

                fuzzed_query = urlencode(modified_params, doseq=True)
                fuzzed_url = urlunparse(
                    (parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                     parsed_url.params, fuzzed_query, parsed_url.fragment)
                )
                fuzzed_urls.append(fuzzed_url)
                self.logger.debug(f"Generated fuzzed URL: {fuzzed_url}")
        
        self.logger.info(f"Generated {len(fuzzed_urls)} fuzzed URLs for {url}.")
        return fuzzed_urls

    def fuzz_post_data(self, url, original_data, params_to_fuzz=None, payloads=None):
        """
        Fuzzes POST request data (form fields).
        :param url: The URL to send the POST request to.
        :param original_data: The original dictionary of POST data.
        :param params_to_fuzz: A list of parameter names to fuzz. If None, all parameters will be fuzzed.
        :param payloads: A list of payloads to use. If None, common_payloads will be used.
        :return: A list of fuzzed POST data dictionaries.
        """
        fuzzed_data_list = []
        target_payloads = payloads if payloads is not None else self._generate_all_payloads()

        if not original_data:
            self.logger.debug(f"No POST data provided for {url} to fuzz.")
            return []

        params_to_operate_on = params_to_fuzz if params_to_fuzz else original_data.keys()

        for param_name in params_to_operate_on:
            if param_name not in original_data:
                continue

            for payload in target_payloads:
                modified_data = original_data.copy()
                modified_data[param_name] = payload
                fuzzed_data_list.append(modified_data)
                self.logger.debug(f"Generated fuzzed POST data for '{param_name}': {modified_data}")

        self.logger.info(f"Generated {len(fuzzed_data_list)} fuzzed POST data sets for {url}.")
        return fuzzed_data_list

    # You could extend this with fuzz_headers, fuzz_json_body, etc.