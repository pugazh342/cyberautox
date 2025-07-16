# modules/reconnaissance/osint_harvester.py
import shodan
from core.utils.config_manager import Config
from core.utils.logger import CyberLogger # Import logger

class OSINTHarvester:
    def __init__(self):
        self.logger = CyberLogger() # Initialize logger
        self.config = Config().get('shodan')
        api_key = self.config.get('api_key')
        if not api_key:
            self.logger.error("Shodan API key not found in config. Please set it in configs/api_keys.yml")
            raise ValueError("Shodan API key is missing.")
        self.api = shodan.Shodan(api_key)

    def search_domain(self, domain):
        try:
            # --- TEMPORARY CHANGE FOR FREE KEY TESTING ---
            # Replace the line below with a more basic query if 'search' fails with your free key.
            # For example, to check a specific IP:
            # results = self.api.host('8.8.8.8')
            # For a domain, a free key might not allow 'hostname:domain' search.
            # You might need to just return mock data for now or upgrade your key.

            # Keeping original for now, as it's the intended functionality for paid keys:
            results = self.api.search(f"hostname:{domain}")
            # --- END TEMPORARY CHANGE ---

            return [item['ip_str'] for item in results['matches']]
        except shodan.APIError as e:
            # Use the logger to report the error
            self.logger.error(f"Shodan error during OSINT for {domain}: {e}")
            raise Exception(f"Shodan error: {e}") # Re-raise to be caught by CLI controller
        except Exception as e:
            self.logger.error(f"An unexpected error occurred during OSINT for {domain}: {e}")
            raise Exception(f"Unexpected OSINT error: {e}")