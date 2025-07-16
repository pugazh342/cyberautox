# core/integrations/nmap_controller.py
import subprocess
import sys
from core.utils.logger import CyberLogger # Import CyberLogger
from pathlib import Path

class NmapController:
    def __init__(self):
        self.logger = CyberLogger()
        # You might need to specify the full path to nmap.exe if it's not in your system's PATH
        # For Windows, it might be something like: r"C:\Program Files (x86)\Nmap\nmap.exe"
        # For Linux/macOS, usually just "nmap" is fine if it's in PATH.
        self.nmap_executable = r"D:\CyberAutoX\nmap.exe" 
        
        # Check if nmap executable is found
        if not self._check_nmap_exists():
            self.logger.error(
                f"Nmap executable '{self.nmap_executable}' not found in system PATH. "
                "Please ensure Nmap is installed and added to your system's PATH, "
                "or update 'self.nmap_executable' in nmap_controller.py with the full path."
            )
            self.is_ready = False
        else:
            self.is_ready = True
            self.logger.info(f"Nmap executable found at: {self._check_nmap_exists()}")

    def _check_nmap_exists(self):
        """Checks if the nmap executable is found in PATH or at the specified path."""
        try:
            # Use 'where' on Windows, 'which' on Linux/macOS
            if Path(self.nmap_executable).is_file(): # Check if it's an absolute path directly
                return str(Path(self.nmap_executable).resolve())
            
            check_command = ["where", self.nmap_executable] if sys.platform == "win32" else ["which", self.nmap_executable]
            result = subprocess.run(check_command, capture_output=True, text=True, check=False)
            if result.returncode == 0:
                return result.stdout.strip().splitlines()[0] # Return the first path found
            return None
        except FileNotFoundError:
            return None
        except Exception as e:
            self.logger.warning(f"Error checking Nmap existence: {e}")
            return None

    def run_scan(self, target, options=None):
        """
        Runs an Nmap scan with the specified target and options.
        :param target: The target IP address or hostname.
        :param options: A list of Nmap options (e.g., ['-sV', '-p', '80,443']).
        :return: A tuple (stdout, stderr) of the Nmap process, or (None, error_message) if Nmap is not ready.
        """
        if not self.is_ready:
            return None, "Nmap is not configured correctly. Scan aborted."

        if options is None:
            options = []

        command = [self.nmap_executable, target] + options
        self.logger.info(f"Running Nmap command: {' '.join(command)}")

        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True, # Raise CalledProcessError for non-zero exit codes
                encoding='utf-8' # Ensure consistent text decoding
            )
            self.logger.info("Nmap scan completed successfully.")
            return process.stdout, process.stderr
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Nmap scan failed with error code {e.returncode}: {e.stderr}")
            return e.stdout, e.stderr
        except FileNotFoundError:
            error_msg = f"Nmap executable not found at '{self.nmap_executable}'. Please ensure Nmap is installed and in your system's PATH, or specify the full path in nmap_controller.py."
            self.logger.error(error_msg)
            return None, error_msg
        except Exception as e:
            self.logger.error(f"An unexpected error occurred during Nmap scan: {e}")
            return None, str(e)

# You can add a main block here for quick testing of this module if needed
if __name__ == '__main__':
    # To test this module directly: python core/integrations/nmap_controller.py
    # Requires nmap installed and in PATH
    print("--- Testing NmapController ---")
    
    # Initialize logger (basic setup for standalone test)
    import logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    controller = NmapController()
    
    if controller.is_ready:
        print("\n--- Running basic Nmap scan ---")
        # Use a non-sensitive target like scanme.nmap.org for testing
        stdout, stderr = controller.run_scan("scanme.nmap.org", ['-F']) # -F for fast scan
        
        if stdout:
            print("\nNmap Stdout:\n", stdout)
        if stderr:
            print("\nNmap Stderr:\n", stderr)

        print("\n--- Running Nmap scan with service version detection ---")
        stdout, stderr = controller.run_scan("scanme.nmap.org", ['-sV', '-p', '22,80,443']) # -sV for service version detection
        
        if stdout:
            print("\nNmap Stdout:\n", stdout)
        if stderr:
            print("\nNmap Stderr:\n", stderr)
    else:
        print("NmapController not ready. Please check logs for details.")