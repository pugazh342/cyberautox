# cyberautox.py
import click
import sys
from pathlib import Path
from core.utils.report_generator import generate_report
from core.utils.logger import CyberLogger

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

main_logger = CyberLogger()

@click.group()
def cli():
    """CyberAutoX - Unified Security Toolkit"""
    pass

@cli.command()
@click.option("--target", required=True, help="Target URL")
@click.option("--scan-type", type=click.Choice(['full', 'sqli', 'xss','lfi','rce']), default='full')
@click.option("--interactive", is_flag=True, help="Pause for user confirmation")
def vulnscan(target, scan_type, interactive):
    if interactive:
        click.confirm("Start vulnerability scan?", abort=True)
    """Run vulnerability scans"""
    from modules.vulnerability_scanning.scanner import VulnScanner
    scanner = VulnScanner(target)
    
    results = {}

    scan_map = {
        'sqli': scanner.run_sqlmap,
        'xss': scanner.check_xss,
        'lfi': scanner.check_lfi,
        'rce': scanner.check_rce
    }

    if scan_type == 'full':
        main_logger.info(f"Initiating a FULL vulnerability scan for {target}...")
        for name, method in scan_map.items():
            main_logger.info(f"Running {name.upper()} scan...")
            results[name] = method()
    else:
        main_logger.info(f"Initiating {scan_type.upper()} scan for {target}...")
        results[scan_type] = scan_map[scan_type]()
    
    main_logger.info("--- Scan Summary ---")
    
    all_findings_for_report = []

    if scan_type == 'full':
        for s_type, s_results in results.items():
            if s_results:
                main_logger.info(f"{s_type.upper()} findings: {len(s_results)} detected.")
                all_findings_for_report.extend(s_results)
            else:
                main_logger.info(f"{s_type.upper()} findings: None.")
    else: # Specific scan type
        s_results = results.get(scan_type, [])
        if s_results:
            main_logger.info(f"{scan_type.upper()} findings: {len(s_results)} detected.")
            all_findings_for_report.extend(s_results)
        else:
            main_logger.info(f"{scan_type.upper()} findings: None.")

    report_path = generate_report(scan_type, target, findings=all_findings_for_report)
    
    main_logger.info(f"Scan completed. Detailed report generated at: {report_path}")


@cli.command()
@click.option("--domain", required=True, help="Target domain")
@click.option("--threads", default=10, help="Scanning threads")
def subscan(domain, threads):
    """Run subdomain scan"""
    from modules.reconnaissance.subdomain_scanner import SubdomainScanner
    scanner = SubdomainScanner(domain)
    found_subdomains = scanner.scan(threads)
    if found_subdomains:
        main_logger.info(f"Found {len(found_subdomains)} subdomains for {domain}:")
        for subdomain in found_subdomains:
            main_logger.info(subdomain)
    else:
        main_logger.info(f"No subdomains found for {domain}.")

@cli.command()
@click.option("--domain", required=True, help="Domain for OSINT gathering (e.g., example.com)")
def osint(domain):
    """Perform OSINT gathering using integrated tools like Shodan."""
    from modules.reconnaissance.osint_harvester import OSINTHarvester
    main_logger.info(f"Starting OSINT gathering for domain: {domain}")
    harvester = OSINTHarvester()
    
    ips = harvester.search_domain(domain)
    
    if ips:
        main_logger.info(f"Discovered IPs via Shodan for {domain}: {', '.join(ips)}")
    else:
        main_logger.info(f"No significant OSINT findings for {domain} (or Shodan API not available).")

@cli.command()
@click.option("--target", required=True, help="Target URL (e.g., https://www.cloudflare.com/)")
def waf_detect(target):
    """Detect Web Application Firewall (WAF) protecting the target URL."""
    from modules.waf_bypass.waf_detect import WAFDetector
    main_logger.info(f"Starting WAF detection for: {target}")
    detector = WAFDetector()
    detected_wafs = detector.detect(target)
    
    if detected_wafs and "No WAF detected" not in detected_wafs:
        main_logger.info(f"WAF Detection Results: {', '.join(detected_wafs)} detected on {target}")
    else:
        main_logger.info(f"WAF Detection Results: No known WAFs detected on {target}")

@cli.command()
@click.option("--target", required=True, help="Target IP or hostname (e.g., scanme.nmap.org)")
@click.option("--scan-type", type=click.Choice(['full', 'port', 'service', 'os']), default='full',
              help="Type of network scan to perform.")
@click.option("--ports", help="Comma-separated list of ports for 'port' or 'service' scan (e.g., '22,80,443').")
def netscan(target, scan_type, ports):
    """Perform network vulnerability assessment (VAPT) using Nmap."""
    from modules.network_vapt.scanner import NetworkVAPTScanner
    main_logger.info(f"Starting network scan for: {target} (Type: {scan_type})")
    scanner = NetworkVAPTScanner()
    
    if not scanner.nmap_controller.is_ready:
        main_logger.error("Nmap is not configured correctly. Cannot perform network scan.")
        return

    scan_output = ""
    if scan_type == 'full':
        scan_output = scanner.perform_full_scan(target)
    elif scan_type == 'port':
        scan_output = scanner.perform_port_scan(target, ports)
    elif scan_type == 'service':
        scan_output = scanner.perform_service_version_detection(target, ports)
    elif scan_type == 'os':
        scan_output = scanner.perform_os_detection(target)
    
    main_logger.info(f"--- Network Scan Results for {target} ({scan_type.upper()} Scan) ---")
    main_logger.info(scan_output)
    main_logger.info(f"Network scan for {target} completed.")

@cli.command()
@click.option("--target", required=True, help="Target URL with a parameter (e.g., http://example.com/file.php?name=test)")
def path_traversal_scan(target):
    """Scan a target URL for Path Traversal vulnerabilities."""
    from modules.path_traversal.scanner import PathTraversalScanner
    main_logger.info(f"Starting Path Traversal scan for: {target}")
    scanner = PathTraversalScanner()
    
    vulnerabilities = scanner.scan(target)
    
    if vulnerabilities:
        main_logger.success(f"Found {len(vulnerabilities)} Path Traversal vulnerabilities for {target}:")
        for vuln in vulnerabilities:
            main_logger.success(f"  - Vulnerable URL: {vuln['url']} (Parameter: {vuln['parameter']}, Payload: {vuln['payload_used']})")
    else:
        main_logger.info(f"No Path Traversal vulnerabilities found for {target}.")

@cli.command()
@click.option("--target", required=True, help="Target URL with a form to test (e.g., http://example.com/profile/edit)")
def csrf_scan(target):
    """Scan a target URL for CSRF vulnerabilities by analyzing forms."""
    from modules.csrf.scanner import CSRFScanner
    main_logger.info(f"Starting CSRF scan for: {target}")
    scanner = CSRFScanner()
    
    vulnerabilities = scanner.scan(target)
    
    if vulnerabilities:
        main_logger.success(f"Found {len(vulnerabilities)} CSRF vulnerabilities for {target}:")
        for vuln in vulnerabilities:
            main_logger.success(f"  - Vulnerable Form Action: {vuln['form_action']} (Method: {vuln['method']})")
            main_logger.success(f"    Details: {vuln['details']}")
            main_logger.success(f"    Response Status: {vuln['response_status']}")
            main_logger.success(f"    URL: {vuln['url']}")
    else:
        main_logger.info(f"No CSRF vulnerabilities found for {target}.")

@cli.command()
@click.option("--target", required=True, help="Target URL of the login page (e.g., http://example.com/login.php)")
@click.option("--username-field", default="username", help="Name attribute of the username input field (default: 'username')")
@click.option("--password-field", default="password", help="Name attribute of the password input field (default: 'password')")
@click.option("--submit-field", help="Name attribute of the submit button (optional)")
def auth_test(target, username_field, password_field, submit_field):
    """Perform authentication testing (e.g., brute-force) on a login page."""
    from modules.auth_testing.scanner import AuthTester
    main_logger.info(f"Starting Authentication Testing for: {target}")
    tester = AuthTester()
    
    found_credentials = tester.scan(target, username_field, password_field, submit_field)
    
    if found_credentials:
        main_logger.success(f"Found {len(found_credentials)} valid credentials for {target}:")
        for cred in found_credentials:
            main_logger.success(f"  - Valid Credential: {cred['username']}:{cred['password']}")
            main_logger.success(f"    Details: {cred['details']}")
            main_logger.success(f"    URL: {cred['url']}")
    else:
        main_logger.info(f"No weak/default credentials found for {target}.")

@cli.command()
@click.option("--base-api-url", required=True, help="The base URL of the API (e.g., https://api.example.com/v1/)")
@click.option("--endpoint-pattern", required=True, help="Pattern for a vulnerable endpoint with ID placeholder (e.g., 'users/{}')")
@click.option("--initial-id", default="1", help="An ID expected to be accessible (e.g., current user's ID)")
@click.option("--test-ids", default="2,999,admin", help="Comma-separated list of IDs to test for unauthorized access")
def api_scan(base_api_url, endpoint_pattern, initial_id, test_ids):
    """Scan a target API for security vulnerabilities like Broken Object Level Authorization (BOLA)."""
    from modules.api_security.scanner import APISecurityScanner
    main_logger.info(f"Starting API security scan (BOLA) for: {base_api_url}")
    scanner = APISecurityScanner()
    
    # Convert comma-separated string to a list of strings
    test_ids_list = [id.strip() for id in test_ids.split(',')]

    vulnerabilities = scanner.scan(
        api_type="bola",
        base_api_url=base_api_url,
        vulnerable_endpoint_pattern=endpoint_pattern,
        initial_id=initial_id,
        test_ids=test_ids_list
    )
    
    if vulnerabilities:
        main_logger.success(f"Found {len(vulnerabilities)} API security vulnerabilities for {base_api_url}:")
        for vuln in vulnerabilities:
            main_logger.success(f"  - Vulnerability: {vuln['vulnerability']}")
            main_logger.success(f"    URL: {vuln['url']}")
            main_logger.success(f"    Tested ID: {vuln['test_id']}")
            main_logger.success(f"    Details: {vuln['details']}")
    else:
        main_logger.info(f"No API security vulnerabilities found for {base_api_url}.")

@cli.command()
@click.option("--api-endpoint", required=True, help="Full URL of the mobile API endpoint to test (e.g., https://api.example.com/v1/user/data)")
@click.option("--sensitive-keywords", default="email,phone,address", help="Comma-separated list of sensitive data keywords to look for in response")
@click.option("--scan-type", type=click.Choice(['unauthenticated_access']), default='unauthenticated_access',
              help="Type of mobile API scan to perform (default: 'unauthenticated_access')")
def mobile_api_scan(api_endpoint, sensitive_keywords, scan_type):
    """Perform security testing on Mobile Application APIs."""
    from modules.mobile_api.scanner import MobileAPITester
    main_logger.info(f"Starting Mobile API scan ({scan_type}) for: {api_endpoint}")
    tester = MobileAPITester()
    
    sensitive_keywords_list = [kw.strip() for kw in sensitive_keywords.split(',')]

    if scan_type == "unauthenticated_access":
        vulnerabilities = tester.scan(
            scan_type="unauthenticated_access",
            api_endpoint=api_endpoint,
            sensitive_data_keywords=sensitive_keywords_list
        )
    else:
        main_logger.error(f"Unsupported mobile API scan type: {scan_type}")
        return

    if vulnerabilities:
        main_logger.success(f"Found {len(vulnerabilities)} Mobile API vulnerabilities for {api_endpoint}:")
        for vuln in vulnerabilities:
            main_logger.success(f"  - Vulnerability: {vuln['vulnerability']}")
            main_logger.success(f"    URL: {vuln['url']}")
            main_logger.success(f"    Details: {vuln['details']}")
    else:
        main_logger.info(f"No Mobile API vulnerabilities found for {api_endpoint}.")

@cli.command()
@click.option("--target-url-pattern", required=True, help="URL pattern with a placeholder for the target ID (e.g., 'http://example.com/profile/{}')")
@click.option("--cookies", help="JSON string of cookies for an authenticated user (e.g., '{\"PHPSESSID\": \"abc\", \"security\": \"low\"}')")
@click.option("--current-user-id", default="1", help="The ID of the currently authenticated user whose cookies are used for the test.")
@click.option("--target-user-id", default="2", help="The ID of the user whose data/resource we try to access illicitly.")
@click.option("--expected-success-status", default=200, type=int, help="HTTP status code expected for legitimate access (default: 200).")
@click.option("--expected-failure-status", default=403, type=int, help="HTTP status code expected for unauthorized access (default: 403).")
def access_control_scan(target_url_pattern, cookies, current_user_id, target_user_id, expected_success_status, expected_failure_status):
    """Scan for Access Control vulnerabilities, such as Horizontal Privilege Escalation."""
    from modules.access_control.scanner import AccessControlScanner
    import json

    main_logger.info(f"Starting Access Control scan (Horizontal Escalation) for: {target_url_pattern}")
    scanner = AccessControlScanner()
    
    parsed_cookies = {}
    if cookies:
        try:
            parsed_cookies = json.loads(cookies)
        except json.JSONDecodeError:
            main_logger.error("Invalid JSON format for --cookies. Please provide a valid JSON string.")
            return

    vulnerabilities = scanner.scan(
        scan_type="horizontal_escalation",
        vulnerable_url_pattern=target_url_pattern,
        valid_user_cookies=parsed_cookies,
        current_user_id=current_user_id,
        target_user_id=target_user_id,
        expected_success_status=expected_success_status,
        expected_failure_status=expected_failure_status
    )
    
    if vulnerabilities:
        main_logger.success(f"Found {len(vulnerabilities)} Access Control vulnerabilities for {target_url_pattern}:")
        for vuln in vulnerabilities:
            main_logger.success(f"  - Vulnerability: {vuln['vulnerability']}")
            main_logger.success(f"    URL: {vuln['url']}")
            main_logger.success(f"    Attempted ID: {vuln['attempted_id']}")
            main_logger.success(f"    Details: {vuln['details']}")
    else:
        main_logger.info(f"No Access Control vulnerabilities found for {target_url_pattern}.")

@cli.command()
@click.option("--jwt-token", required=True, help="The original JWT token to test (e.g., 'eyJhbGci...').")
@click.option("--target-url", required=True, help="The URL where the JWT is typically sent for authenticated actions (e.g., 'http://example.com/api/profile').")
@click.option("--method", default="GET", type=click.Choice(['GET', 'POST', 'PUT', 'DELETE']), help="HTTP method for the request (default: GET).")
@click.option("--headers", help="JSON string of additional headers (e.g., '{\"Content-Type\": \"application/json\"}').")
@click.option("--data", help="Request body data for POST/PUT requests (raw string).")
@click.option("--json-data", help="JSON string for request body data for POST/PUT requests.")
@click.option("--cookies", help="JSON string of cookies for the request.")
@click.option("--scan-type", default="none_algorithm", type=click.Choice(['none_algorithm']), help="Type of JWT scan to perform (default: 'none_algorithm').")
def jwt_scan(jwt_token, target_url, method, headers, data, json_data, cookies, scan_type):
    """Scan for JSON Web Token (JWT) vulnerabilities, such as 'none' algorithm bypass."""
    from modules.jwt.scanner import JWTSecurityScanner
    import json

    main_logger.info(f"Starting JWT security scan ({scan_type}) for: {target_url}")
    scanner = JWTSecurityScanner()

    parsed_headers = {}
    if headers:
        try:
            parsed_headers = json.loads(headers)
        except json.JSONDecodeError:
            main_logger.error("Invalid JSON format for --headers. Please provide a valid JSON string.")
            return
            
    parsed_json_data = None
    if json_data:
        try:
            parsed_json_data = json.loads(json_data)
        except json.JSONDecodeError:
            main_logger.error("Invalid JSON format for --json-data. Please provide a valid JSON string.")
            return

    parsed_cookies = {}
    if cookies:
        try:
            parsed_cookies = json.loads(cookies)
        except json.JSONDecodeError:
            main_logger.error("Invalid JSON format for --cookies. Please provide a valid JSON string.")
            return

    if scan_type == "none_algorithm":
        vulnerabilities = scanner.scan(
            scan_type="none_algorithm",
            jwt_token=jwt_token,
            target_url=target_url,
            method=method,
            headers=parsed_headers,
            data=data,
            json_data=parsed_json_data,
            cookies=parsed_cookies
        )
    else:
        main_logger.error(f"Unsupported JWT scan type: {scan_type}")
        return

    if vulnerabilities:
        main_logger.success(f"Found {len(vulnerabilities)} JWT vulnerabilities for {target_url}:")
        for vuln in vulnerabilities:
            main_logger.success(f"  - Vulnerability: {vuln['vulnerability']}")
            main_logger.success(f"    URL: {vuln['url']}")
            main_logger.success(f"    Details: {vuln['details']}")
            if 'modified_token' in vuln:
                main_logger.success(f"    Modified Token: {vuln['modified_token']}")
    else:
        main_logger.info(f"No JWT vulnerabilities found for {target_url}.")

@cli.command()
@click.option("--login-url", required=True, help="The URL of the login page (e.g., 'http://example.com/login.php').")
@click.option("--username-field", default="username", help="The name attribute of the username input field (default: 'username').")
@click.option("--password-field", default="password", help="The name attribute of the password input field (default: 'password').")
@click.option("--username", required=True, help="A valid username to use for login attempts.")
@click.option("--password", required=True, help="The password for the provided username.")
@click.option("--num-attempts", default=5, type=int, help="Number of times to attempt login and capture session IDs (default: 5).")
@click.option("--cookie-name", default="PHPSESSID", help="The name of the session cookie to extract (default: 'PHPSESSID').")
@click.option("--scan-type", default="predictable_session_ids", type=click.Choice(['predictable_session_ids']), help="Type of session attack scan to perform (default: 'predictable_session_ids').")
def session_attack_scan(login_url, username_field, password_field, username, password, num_attempts, cookie_name, scan_type):
    """Scan for Session Attack vulnerabilities, such as predictable session IDs or session fixation."""
    from modules.session_attack.scanner import SessionAttacker

    main_logger.info(f"Starting Session Attack scan ({scan_type}) for: {login_url}")
    scanner = SessionAttacker()

    if scan_type == "predictable_session_ids":
        vulnerabilities = scanner.scan(
            scan_type="predictable_session_ids",
            login_url=login_url,
            username_field=username_field,
            password_field=password_field,
            username=username,
            password=password,
            num_attempts=num_attempts,
            cookie_name=cookie_name
        )
    else:
        main_logger.error(f"Unsupported session attack scan type: {scan_type}")
        return

    if vulnerabilities:
        main_logger.success(f"Found {len(vulnerabilities)} Session Attack vulnerabilities for {login_url}:")
        for vuln in vulnerabilities:
            main_logger.success(f"  - Vulnerability: {vuln['vulnerability']}")
            main_logger.success(f"    URL: {vuln['url']}")
            main_logger.success(f"    Details: {vuln['details']}")
            if 'captured_ids_count' in vuln:
                main_logger.success(f"    Captured ID Counts: {vuln['captured_ids_count']}")
    else:
        main_logger.info(f"No Session Attack vulnerabilities found for {login_url}.")

@cli.command()
@click.option("--upload-url", required=True, help="The URL of the file upload endpoint (e.g., 'http://example.com/upload_image.php').")
@click.option("--file-field-name", required=True, help="The name of the file input field in the HTML form (e.g., 'file', 'image').")
@click.option("--ssrf-payload-url", default="http://127.0.0.1/nonexistent", help="The internal/external URL the server should fetch if vulnerable to SSRF (default: 'http://127.0.0.1/nonexistent').")
@click.option("--filename", default="test_ssrf.png", help="The name to give the uploaded file (default: 'test_ssrf.png').")
@click.option("--mime-type", default="image/png", help="The MIME type of the uploaded file (default: 'image/png').")
@click.option("--additional-form-data", help="JSON string of additional form data (e.g., '{\"csrf_token\": \"abc\"}').")
@click.option("--expected-ssrf-success-keyword", help="A keyword expected in the response if the SSRF payload was processed successfully.")
@click.option("--scan-type", default="ssrf_via_upload", type=click.Choice(['ssrf_via_upload']), help="Type of SSRF/File Upload scan to perform (default: 'ssrf_via_upload').")
def ssrf_fileupload_scan(upload_url, file_field_name, ssrf_payload_url, filename, mime_type, additional_form_data, expected_ssrf_success_keyword, scan_type):
    """Scan for Server-Side Request Forgery (SSRF) vulnerabilities via file upload mechanisms."""
    from modules.ssrf_fileupload.scanner import SSRFFileUploader
    import json

    main_logger.info(f"Starting SSRF/File Upload scan ({scan_type}) for: {upload_url}")
    scanner = SSRFFileUploader()

    parsed_additional_form_data = None
    if additional_form_data:
        try:
            parsed_additional_form_data = json.loads(additional_form_data)
        except json.JSONDecodeError:
            main_logger.error("Invalid JSON format for --additional-form-data. Please provide a valid JSON string.")
            return

    if scan_type == "ssrf_via_upload":
        vulnerabilities = scanner.scan(
            scan_type="ssrf_via_upload",
            upload_url=upload_url,
            file_field_name=file_field_name,
            ssrf_payload_url=ssrf_payload_url,
            filename=filename,
            mime_type=mime_type,
            additional_form_data=parsed_additional_form_data,
            expected_ssrf_success_keyword=expected_ssrf_success_keyword
        )
    else:
        main_logger.error(f"Unsupported SSRF/File Upload scan type: {scan_type}")
        return

    if vulnerabilities:
        main_logger.success(f"Found {len(vulnerabilities)} SSRF/File Upload vulnerabilities for {upload_url}:")
        for vuln in vulnerabilities:
            main_logger.success(f"  - Vulnerability: {vuln['vulnerability']}")
            main_logger.success(f"    URL: {vuln['url']}")
            main_logger.success(f"    Details: {vuln['details']}")
            main_logger.success(f"    SSRF Payload URL: {vuln['ssrf_payload_url']}")
            if 'response_snippet' in vuln:
                main_logger.success(f"    Response Snippet: {vuln['response_snippet']}")
    else:
        main_logger.info(f"No SSRF via File Upload vulnerabilities found for {upload_url}.")

@cli.command()
@click.option("--domain-controller-ip", required=True, help="IP address or hostname of a Domain Controller (e.g., '192.168.1.100').")
@click.option("--domain-name", required=True, help="The target domain name (e.g., 'corp.example.com').")
@click.option("--username", help="Username for authenticated access (optional).")
@click.option("--password", help="Password for authenticated access (optional).")
@click.option("--scan-type", default="full_enumeration", type=click.Choice(['full_enumeration', 'domain_info', 'user_enum']), help="Type of Active Directory scan to perform (default: 'full_enumeration').")
def ad_scan(domain_controller_ip, domain_name, username, password, scan_type):
    """Perform Active Directory security assessment, including enumeration and potential vulnerability checks."""
    from modules.active_directory.scanner import ADScanner

    main_logger.info(f"Starting Active Directory scan ({scan_type}) for: {domain_name} (DC: {domain_controller_ip})")
    scanner = ADScanner()

    results = scanner.scan(
        scan_type=scan_type,
        domain_controller_ip=domain_controller_ip,
        domain_name=domain_name,
        username=username,
        password=password
    )

    if results:
        main_logger.info(f"--- Active Directory Scan Results for {domain_name} ({scan_type.upper()} Scan) ---")
        if "domain_info" in results:
            main_logger.info("\nDomain Information:")
            for key, value in results["domain_info"].items():
                main_logger.info(f"  {key.replace('_', ' ').title()}: {value}")
        
        if "users" in results:
            main_logger.info("\nEnumerated Users:")
            for user in results["users"]:
                main_logger.info(f"  - Username: {user['username']}, Full Name: {user['full_name']}, Email: {user['email']}")
        
        # Add a section for actual vulnerabilities if the scanner.vulnerabilities list is populated
        if hasattr(scanner, 'vulnerabilities') and scanner.vulnerabilities:
            main_logger.success("\nActive Directory Vulnerabilities Found:")
            for vuln in scanner.vulnerabilities:
                main_logger.success(f"  - Vulnerability: {vuln['vulnerability']}")
                main_logger.success(f"    Details: {vuln['details']}")
    else:
        main_logger.info(f"No Active Directory scan results obtained for {domain_name} with scan type {scan_type}.")

@cli.command()
@click.option("--target-content", help="Direct content of a CI/CD configuration file to scan.")
@click.option("--file-path", type=click.Path(exists=True, dir_okay=False, readable=True), help="Path to a CI/CD configuration file to scan.")
@click.option("--scan-type", default="full_scan", type=click.Choice(['full_scan', 'exposed_keys', 'insecure_pipelines']), help="Type of CI/CD scan to perform (default: 'full_scan').")
def ci_cd_scan(target_content, file_path, scan_type):
    """Scan CI/CD configurations for security misconfigurations and vulnerabilities."""
    from modules.ci_cd.scanner import CICDRaider

    main_logger.info(f"Starting CI/CD scan ({scan_type})...")
    scanner = CICDRaider()

    if not target_content and not file_path:
        main_logger.error("Error: Either --target-content or --file-path must be provided.")
        return

    vulnerabilities = scanner.scan(
        scan_type=scan_type,
        target_content=target_content,
        file_path=file_path
    )

    if vulnerabilities:
        main_logger.success(f"Found {len(vulnerabilities)} CI/CD vulnerabilities:")
        for vuln in vulnerabilities:
            main_logger.success(f"  - Vulnerability: {vuln['vulnerability']}")
            main_logger.success(f"    Details: {vuln['details']}")
            main_logger.success(f"    Severity: {vuln['severity']}")
            main_logger.success(f"    Location: {vuln['location']}")
    else:
        main_logger.info(f"No CI/CD vulnerabilities found for scan type {scan_type}.")

# --- START NEW CLOUD COMMAND ---
@cli.command()
@click.option("--bucket-url", help="URL of the cloud storage bucket to check for public access (e.g., 'http://bucket-name.s3.amazonaws.com/').")
@click.option("--expected-content-keyword", help="A keyword expected in the content if the bucket is publicly accessible (optional).")
@click.option("--scan-type", default="public_bucket_access", type=click.Choice(['public_bucket_access']), help="Type of cloud scan to perform (default: 'public_bucket_access').")
def cloud_scan(bucket_url, expected_content_keyword, scan_type):
    """Perform cloud security assessment, such as checking for publicly accessible storage buckets."""
    from modules.cloud.scanner import CloudAuditor

    main_logger.info(f"Starting Cloud scan ({scan_type})...")
    auditor = CloudAuditor()

    # In a real tool, you would handle authentication here (e.g., AWS_PROFILE, Azure_CLI_AUTH)
    # For now, we rely on public URLs for simulation.

    results = auditor.scan(
        scan_type=scan_type,
        bucket_url=bucket_url,
        expected_public_content_keyword=expected_content_keyword # Pass the keyword if provided
    )

    if results:
        main_logger.success(f"Found {len(results)} Cloud vulnerabilities:")
        for vuln in results:
            main_logger.success(f"  - Vulnerability: {vuln['vulnerability']}")
            main_logger.success(f"    Details: {vuln['details']}")
            main_logger.success(f"    Severity: {vuln['severity']}")
            main_logger.success(f"    Location: {vuln['location']}")
            if 'response_status' in vuln:
                main_logger.success(f"    Response Status: {vuln['response_status']}")
    else:
        main_logger.info(f"No Cloud vulnerabilities detected for scan type {scan_type}.")
# --- END NEW CLOUD COMMAND ---

if __name__ == '__main__':
    cli()