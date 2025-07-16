# core/utils/config_manager.py
import yaml
from pathlib import Path
import logging # <--- CHANGED: Import standard logging module instead of CyberLogger

class Config:
    _instance = None
    _config_data = {}
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Config, cls).__new__(cls)
            cls._instance.logger = logging.getLogger(__name__) # <--- CHANGED: Use standard logger
            cls._instance._load_configs()
        return cls._instance

    def _load_configs(self):
        """Loads configuration from global.yml and api_keys.yml."""
        config_dir = Path("configs/")
        
        global_config_path = config_dir / "global.yml"
        api_keys_config_path = config_dir / "api_keys.yml"

        # Load global.yml
        if global_config_path.exists():
            try:
                with open(global_config_path, 'r') as f:
                    self._config_data.update(yaml.safe_load(f) or {}) # .update({}) for empty files
                self.logger.info(f"Loaded configuration from {global_config_path}")
            except yaml.YAMLError as e:
                self.logger.error(f"Error parsing global.yml: {e}")
            except Exception as e:
                self.logger.error(f"Failed to read global.yml: {e}")
        else:
            self.logger.warning(f"Global config file not found: {global_config_path}")

        # Load api_keys.yml
        if api_keys_config_path.exists():
            try:
                with open(api_keys_config_path, 'r') as f:
                    api_keys = yaml.safe_load(f)
                    if api_keys: # Ensure api_keys is not None if file is empty
                        self._config_data.update(api_keys)
                self.logger.info(f"Loaded API keys from {api_keys_config_path}")
            except yaml.YAMLError as e:
                self.logger.error(f"Error parsing api_keys.yml: {e}")
            except Exception as e:
                self.logger.error(f"Failed to read api_keys.yml: {e}")
        else:
            self.logger.warning(f"API keys config file not found: {api_keys_config_path}. Creating a placeholder.")
            self._create_placeholder_api_keys_file(api_keys_config_path)

    def _create_placeholder_api_keys_file(self, path):
        """Creates a placeholder api_keys.yml if it doesn't exist."""
        try:
            placeholder_content = """# configs/api_keys.yml
# This file stores API keys for external services.
# Replace 'YOUR_SHODAN_API_KEY' with your actual Shodan API key.
shodan:
  api_key: YOUR_SHODAN_API_KEY

# Add other API keys as needed:
# censys:
#   api_id: YOUR_CENSYS_API_ID
#   api_secret: YOUR_CENSYS_API_SECRET
"""
            with open(path, 'w') as f:
                f.write(placeholder_content)
            self.logger.info(f"Created placeholder {path}. Please fill in your API keys.")
        except Exception as e:
            self.logger.error(f"Failed to create placeholder api_keys.yml: {e}")

    def get(self, key, default=None):
        """Retrieves a configuration value by key."""
        return self._config_data.get(key, default)

    def get_nested(self, *keys, default=None):
        """Retrieves a nested configuration value by multiple keys."""
        value = self._config_data
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value

# Example Usage (for testing purposes, not part of the class)
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    print("--- Testing ConfigManager ---")
    
    config = Config()

    shodan_key = config.get_nested('shodan', 'api_key')
    print(f"Shodan API Key: {shodan_key}")

    scan_threads = config.get('scan_threads')
    print(f"Scan Threads: {scan_threads}")

    non_existent = config.get('non_existent_key', 'default_value')
    print(f"Non-existent key with default: {non_existent}")