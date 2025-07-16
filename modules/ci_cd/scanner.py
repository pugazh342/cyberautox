# modules/ci_cd/scanner.py
from core.utils.logger import CyberLogger
import os

class CICDRaider:
    def __init__(self):
        self.logger = CyberLogger()
        self.vulnerabilities = []
        # In a real scenario, you'd initialize clients for specific CI/CD platforms
        # e.g., self.jenkins_client = JenkinsAPI(...)
        # self.gitlab_client = GitLabAPI(...)

    def check_exposed_api_keys(self, config_content):
        """
        Scans provided configuration content for patterns of exposed API keys.
        This is a simulated check. In a real scenario, it would parse actual CI/CD config files.

        :param config_content: String content of a configuration file (e.g., .gitlab-ci.yml, Jenkinsfile).
        :return: List of findings if exposed keys are detected.
        """
        findings = []
        self.logger.info("Checking for exposed API keys in CI/CD configuration...")
        
        # Simulated patterns for common API keys
        api_key_patterns = {
            "AWS_ACCESS_KEY_ID": r"AKIA[0-9A-Z]{16}",
            "AWS_SECRET_ACCESS_KEY": r"([A-Za-z0-9+/]{40}|[A-Za-z0-9+/]{48})", # More generic for base64-like
            "GITLAB_TOKEN": r"(glpat-[0-9a-zA-Z\-_]{20,})",
            "GITHUB_TOKEN": r"ghp_[0-9a-zA-Z]{36}",
            "STRIPE_API_KEY": r"sk_live_[0-9a-zA-Z]{24}",
            "API_KEY": r"(api_key|token|secret)[=:\s\"']{1,4}([a-zA-Z0-9_\-]{16,64})" # Generic key=value
        }

        for key_name, pattern in api_key_patterns.items():
            import re
            match = re.search(pattern, config_content)
            if match:
                finding = {
                    "vulnerability": f"Exposed {key_name}",
                    "details": f"Potential {key_name} found in configuration content. Detected pattern: '{match.group(0)}'",
                    "severity": "Critical",
                    "location": "CI/CD Configuration"
                }
                self.vulnerabilities.append(finding)
                findings.append(finding)
                self.logger.warning(f"Detected exposed {key_name}: {match.group(0)}")
        
        if not findings:
            self.logger.info("No exposed API keys detected in the provided content (simulated check).")
        return findings

    def check_insecure_pipeline_definitions(self, pipeline_config_content):
        """
        Scans provided pipeline configuration content for common insecure practices.
        This is a simulated check.

        :param pipeline_config_content: String content of a pipeline definition file (e.g., .travis.yml, Jenkinsfile).
        :return: List of findings if insecure practices are detected.
        """
        findings = []
        self.logger.info("Checking for insecure pipeline definitions...")

        # Simulated insecure patterns
        insecure_patterns = {
            "Hardcoded Credentials": r"password:\s*\"[^\"]+\"|secret:\s*'[^\']+'",
            "Unrestricted Permissions": r"allow_unauthenticated:\s*true|all_permissions:\s*true",
            "Insecure Docker Builds": r"docker\s+build\s+\.",
            "Arbitrary Code Execution": r"eval\s+\$",
            "Weak Checkout Policies": r"git\s+clone\s+--depth\s+1\s+--unrestricted"
        }

        for issue_name, pattern in insecure_patterns.items():
            import re
            match = re.search(pattern, pipeline_config_content, re.IGNORECASE)
            if match:
                finding = {
                    "vulnerability": f"Insecure Pipeline Definition: {issue_name}",
                    "details": f"Possible insecure practice '{issue_name}' detected. Pattern: '{match.group(0)}'",
                    "severity": "High",
                    "location": "CI/CD Pipeline Definition"
                }
                self.vulnerabilities.append(finding)
                findings.append(finding)
                self.logger.warning(f"Detected insecure practice: {issue_name}")
        
        if not findings:
            self.logger.info("No immediate insecure pipeline definitions detected (simulated check).")
        return findings

    def scan(self, scan_type="full_scan", **kwargs):
        """
        Main entry point for CI/CD security scans.
        
        :param scan_type: Type of CI/CD scan to perform (e.g., "full_scan", "exposed_keys", "insecure_pipelines").
        :param kwargs: Arguments specific to the scan type, usually 'target_content' or 'file_path'.
        """
        self.vulnerabilities = [] # Reset for each scan call
        target_content = kwargs.get('target_content')
        file_path = kwargs.get('file_path')

        if not target_content and file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    target_content = f.read()
                self.logger.info(f"Loaded content from file: {file_path}")
            except FileNotFoundError:
                self.logger.error(f"File not found: {file_path}")
                return []
            except Exception as e:
                self.logger.error(f"Error reading file {file_path}: {e}")
                return []

        if not target_content:
            self.logger.error("No content provided for CI/CD scan. Please provide --target-content or --file-path.")
            return []

        if scan_type == "full_scan" or scan_type == "exposed_keys":
            self.check_exposed_api_keys(target_content)
        
        if scan_type == "full_scan" or scan_type == "insecure_pipelines":
            self.check_insecure_pipeline_definitions(target_content)
        
        if not self.vulnerabilities:
            self.logger.info(f"No CI/CD vulnerabilities detected for scan type: {scan_type}")
        
        return self.vulnerabilities

# --- For direct testing of this module ---
if __name__ == '__main__':
    # Set up basic logging for standalone test
    import logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    print("--- Testing CICDRaider ---")
    scanner = CICDRaider()

    # --- Test 1: Simulate scan with a dummy Jenkinsfile (no vulnerabilities) ---
    print("\n--- Test Case 1: Dummy Jenkinsfile (No Vulnerabilities) ---")
    jenkinsfile_content_clean = """
    pipeline {
        agent any
        stages {
            stage('Build') {
                steps {
                    echo 'Building...'
                    sh 'npm install'
                    sh 'npm test'
                }
            }
            stage('Deploy') {
                steps {
                    echo 'Deploying...'
                }
            }
        }
    }
    """
    results_clean = scanner.scan(scan_type="full_scan", target_content=jenkinsfile_content_clean)
    if results_clean:
        print("\nCI/CD Vulnerabilities Found (Test 1):")
        for vuln in results_clean:
            print(f"  - {vuln['vulnerability']}: {vuln['details']}")
    else:
        print("\nNo CI/CD vulnerabilities found for Test Case 1 (as expected).")

    # --- Test 2: Simulate scan with a dummy GitLab CI with exposed key ---
    print("\n--- Test Case 2: Dummy GitLab CI (Exposed API Key) ---")
    gitlab_ci_content_exposed_key = """
    stages:
      - deploy

    deploy-job:
      stage: deploy
      script:
        - echo "Deploying to production..."
        - export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
        - echo "AWS_SECRET_ACCESS_KEY='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"
        - some_deployment_script.sh
    """
    results_exposed = scanner.scan(scan_type="full_scan", target_content=gitlab_ci_content_exposed_key)
    if results_exposed:
        print("\nCI/CD Vulnerabilities Found (Test 2):")
        for vuln in results_exposed:
            print(f"  - {vuln['vulnerability']}: {vuln['details']}")
    else:
        print("\nNo CI/CD vulnerabilities found for Test Case 2 (unexpected).")

    # --- Test 3: Simulate scan with insecure Docker build ---
    print("\n--- Test Case 3: Insecure Docker Build ---")
    insecure_docker_ci_content = """
    build_app:
      stage: build
      script:
        - echo "Building Docker image..."
        - docker build . -f Dockerfile.dev
        - echo "Running insecure command: eval $(cat /etc/passwd)"
    """
    results_insecure_docker = scanner.scan(scan_type="full_scan", target_content=insecure_docker_ci_content)
    if results_insecure_docker:
        print("\nCI/CD Vulnerabilities Found (Test 3):")
        for vuln in results_insecure_docker:
            print(f"  - {vuln['vulnerability']}: {vuln['details']}")
    else:
        print("\nNo CI/CD vulnerabilities found for Test Case 3 (unexpected).")

    # --- Test 4: Scan from a dummy file (create this file first for testing) ---
    dummy_file_path = "temp_ci_cd_config.txt"
    with open(dummy_file_path, "w") as f:
        f.write("A fake config with GITLAB_TOKEN=glpat-1234567890abcdefghijklmnopqrstuv")

    print(f"\n--- Test Case 4: Scan from file '{dummy_file_path}' ---")
    results_file_scan = scanner.scan(scan_type="exposed_keys", file_path=dummy_file_path)
    if results_file_scan:
        print("\nCI/CD Vulnerabilities Found (Test 4):")
        for vuln in results_file_scan:
            print(f"  - {vuln['vulnerability']}: {vuln['details']}")
    else:
        print("\nNo CI/CD vulnerabilities found for Test Case 4 (unexpected).")
    
    # Clean up dummy file
    if os.path.exists(dummy_file_path):
        os.remove(dummy_file_path)