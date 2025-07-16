import subprocess
import json
from pathlib import Path
from core.utils.logger import CyberLogger

class SqlmapWrapper:
    def __init__(self):
        self.logger = CyberLogger()
        # --- IMPORTANT: REPLACE THE PATH BELOW WITH YOUR ACTUAL, FULL PATH TO sqlmap.py ---
        # Example: r"C:\Users\YourUser\Downloads\sqlmap-dev\sqlmap.py"
        # Example: r"D:\MyTools\sqlmap\sqlmap.py"
        self.sqlmap_command_prefix = ["python", r"D:\CyberAutoX\sqlmap\sqlmap.py"] # <--- REPLACE THIS PATH!

    def _run_sqlmap_command(self, command_args):
        """Executes sqlmap command and captures output."""
        full_command = self.sqlmap_command_prefix + command_args # Use the defined prefix
        self.logger.info(f"Running sqlmap command: {' '.join(full_command)}")
        try:
            result = subprocess.run(full_command, capture_output=True, text=True, check=False)
            self.logger.debug(f"Sqlmap stdout:\n{result.stdout}")
            if result.stderr:
                self.logger.error(f"Sqlmap stderr:\n{result.stderr}")
            return result
        except FileNotFoundError:
            self.logger.error(f"Python or the specified sqlmap.py script not found. Please verify paths in sqlmap_wrapper.py.")
            return None
        except Exception as e:
            self.logger.error(f"Error executing sqlmap: {e}")
            return None

    def scan(self, target_url, options=None):
        """
        Runs a basic sqlmap scan on the target URL.
        :param target_url: The URL to scan.
        :param options: A list of additional sqlmap options (e.g., ['--dbs', '--batch']).
        :return: A list of findings or an empty list.
        """
        self.logger.info(f"Starting SQL Injection scan (via sqlmap) for: {target_url}")
        
        # Base sqlmap command arguments
        # --batch: never ask for user input, use default behavior
        # --risk=3 --level=3: Common levels for broader detection
        # --crawl=1: basic crawling (optional, consider WebCrawler for more control)
        # --dump-format=JSON (if you parse sqlmap's JSON reports, not just stdout)
        base_args = [
            "-u", target_url,
            "--batch",
            "--risk=3",
            "--level=3",
            "--random-agent" # Use a random user agent
        ]
        
        # Add any custom options provided
        if options:
            base_args.extend(options)

        result = self._run_sqlmap_command(base_args)

        findings = []
        if result and result.stdout:
            # Basic parsing: look for common indicators of vulnerability
            if "sql injection was detected" in result.stdout.lower() or \
               "is vulnerable" in result.stdout.lower() or \
               "[v]" in result.stdout.lower(): # sqlmap uses [V] for vulnerable parameters
                
                self.logger.warning(f"Potential SQLi vulnerability detected by sqlmap for {target_url}")
                
                # Try to extract more details. sqlmap often prints the vulnerable parameter.
                # This parsing can be complex, for now, we'll just capture the essential finding.
                findings.append({
                    "url": target_url,
                    "payload": "sqlmap detected injection", # Or try to extract from stdout
                    "details": result.stdout.splitlines()[-5:], # Get last few lines for context
                    "tool": "sqlmap"
                })
        
        if not findings:
            self.logger.info(f"No SQL Injection vulnerabilities detected by sqlmap for {target_url}.")

        return findings

# Example usage (for testing purposes, not part of the class)
if __name__ == '__main__':
    # This block only runs if you execute sqlmap_wrapper.py directly
    # python core/integrations/sqlmap_wrapper.py
    sqlmap_wrapper = SqlmapWrapper()
    
    # Test with a known vulnerable URL (replace with a safe test target if using in prod)
    # Example for DVWA/bWAPP: http://localhost/bWAPP/sqli_1.php?title=a
    test_target = "http://testphp.vulnweb.com/listproducts.php?cat=1" # Example target with a GET parameter
    
    # You can add options like '--dbs' or '--tables'
    sqli_findings = sqlmap_wrapper.scan(test_target, options=['--banner'])
    
    if sqli_findings:
        print("\nSQL Injection findings:")
        for finding in sqli_findings:
            print(json.dumps(finding, indent=2))
    else:
        print("\nNo SQL Injection findings from test scan.")