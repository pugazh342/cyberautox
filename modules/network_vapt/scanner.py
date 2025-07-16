# modules/network_vapt/scanner.py
from core.integrations.nmap_controller import NmapController
from core.utils.logger import CyberLogger

class NetworkVAPTScanner:
    def __init__(self):
        self.logger = CyberLogger()
        self.nmap_controller = NmapController()
        
        if not self.nmap_controller.is_ready:
            self.logger.error("NmapController is not ready. Network VAPT scans may not function.")

    def perform_port_scan(self, target, ports=None):
        """
        Performs a basic port scan on the target.
        :param target: IP address or hostname.
        :param ports: Comma-separated list of ports (e.g., "21,22,80,443,8080") or None for common ports.
        :return: Nmap stdout or error message.
        """
        self.logger.info(f"Starting port scan for {target}...")
        options = []
        if ports:
            options.extend(['-p', ports])
        else:
            # Default to a fast scan of common ports if no specific ports are provided
            options.append('-F') # Fast scan (scans top 1000 common ports)

        stdout, stderr = self.nmap_controller.run_scan(target, options)
        
        if stdout:
            self.logger.info(f"Port scan for {target} completed.")
            return stdout
        else:
            self.logger.error(f"Port scan for {target} failed: {stderr}")
            return f"Error: {stderr}"

    def perform_service_version_detection(self, target, ports=None):
        """
        Performs service version detection on the target.
        :param target: IP address or hostname.
        :param ports: Comma-separated list of ports (e.g., "22,80,443") or None for default.
        :return: Nmap stdout or error message.
        """
        self.logger.info(f"Starting service version detection for {target}...")
        options = ['-sV'] # Service version detection
        if ports:
            options.extend(['-p', ports])
        else:
            options.append('-F') # Use fast scan for service detection if no ports specified

        stdout, stderr = self.nmap_controller.run_scan(target, options)

        if stdout:
            self.logger.info(f"Service version detection for {target} completed.")
            return stdout
        else:
            self.logger.error(f"Service version detection for {target} failed: {stderr}")
            return f"Error: {stderr}"

    def perform_os_detection(self, target):
        """
        Performs OS detection on the target.
        :param target: IP address or hostname.
        :return: Nmap stdout or error message.
        """
        self.logger.info(f"Starting OS detection for {target}...")
        options = ['-O'] # OS detection
        stdout, stderr = self.nmap_controller.run_scan(target, options)

        if stdout:
            self.logger.info(f"OS detection for {target} completed.")
            return stdout
        else:
            self.logger.error(f"OS detection for {target} failed: {stderr}")
            return f"Error: {stderr}"
            
    def perform_full_scan(self, target):
        """
        Performs a more comprehensive Nmap scan (e.g., common ports, service versions, OS detection).
        :param target: IP address or hostname.
        :return: Nmap stdout or error message.
        """
        self.logger.info(f"Starting comprehensive Nmap scan for {target}...")
        # -sC: default scripts, -sV: service versions, -O: OS detection, -T4: faster execution, -F: Fast scan common ports
        options = ['-sC', '-sV', '-O', '-T4', '-F'] 
        stdout, stderr = self.nmap_controller.run_scan(target, options)

        if stdout:
            self.logger.info(f"Comprehensive Nmap scan for {target} completed.")
            return stdout
        else:
            self.logger.error(f"Comprehensive Nmap scan for {target} failed: {stderr}")
            return f"Error: {stderr}"

# You can add a main block here for quick testing of this module if needed
if __name__ == '__main__':
    # To test this module directly: python modules/network_vapt/scanner.py
    # Requires nmap installed and configured in nmap_controller.py
    import logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    print("--- Testing NetworkVAPTScanner ---")
    scanner = NetworkVAPTScanner()
    
    if scanner.nmap_controller.is_ready:
        test_target = "scanme.nmap.org" # Always use a target you have permission to scan

        print(f"\n--- Port Scan on {test_target} ---")
        port_scan_output = scanner.perform_port_scan(test_target)
        print(port_scan_output)

        print(f"\n--- Service Version Detection on {test_target} (ports 22,80) ---")
        service_version_output = scanner.perform_service_version_detection(test_target, ports="22,80")
        print(service_version_output)
        
        print(f"\n--- OS Detection on {test_target} ---")
        os_detection_output = scanner.perform_os_detection(test_target)
        print(os_detection_output)

        print(f"\n--- Full Scan on {test_target} ---")
        full_scan_output = scanner.perform_full_scan(test_target)
        print(full_scan_output)
    else:
        print("NetworkVAPTScanner is not ready due to Nmap configuration issues.")