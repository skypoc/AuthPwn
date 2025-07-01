# AuthPwn - Authentication Attack Framework

[![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub stars](https://img.shields.io/github/stars/skypoc/AuthPwn.svg)](https://github.com/skypoc/AuthPwn/stargazers)

AuthPwn is a modular and extensible framework for testing the security of web authentication mechanisms. It automates the enumeration and exploitation of common vulnerabilities in JWT, OAuth, and SAML implementations.

## Disclaimer

⚠️ **This tool is for educational and authorized security testing purposes only.** Do not use it on any system without explicit permission. The user is responsible for any and all damage caused by the use or misuse of this tool. The developers assume no liability and are not responsible for any misuse or damage.

## Features

- **Mechanism Enumeration**: Automatically detects authentication technology (JWT, OAuth, SAML, Basic Auth) used by target applications
- **JWT Attack Suite**:
  - `alg: "none"` attack with multiple case variations to bypass filters
  - Multi-threaded weak secret cracking using wordlists (supports rockyou.txt)
  - Comprehensive JWT decoding and analysis with proper error handling
- **SAML Attack Suite**:
  - Signature Exclusion: Removes signatures from SAML responses to bypass validation
  - Assertion modification for privilege escalation attacks
  - Support for complex XML namespace handling
- **OAuth Attack Suite**:
  - Redirect URI bypass generation with 10+ advanced evasion techniques
  - Support for subdomain confusion, path traversal, and encoding bypasses
- **Performance Features**:
  - Multi-threaded processing for faster attacks (configurable thread count)
  - Progress bars and colored output for better user experience
  - Comprehensive error handling and input validation
  - Graceful interrupt handling (Ctrl+C support)

## Requirements

- Python 3.7 or higher
- Internet connection for target testing
- Optional: wordlist files (rockyou.txt recommended for JWT cracking)

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/skypoc/AuthPwn.git
    cd AuthPwn
    ```

2. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

3. Download wordlists (optional but recommended):
    ```bash
    # For Kali Linux/Parrot OS users:
    sudo apt update && sudo apt install wordlists
    
    # Or download rockyou.txt manually:
    wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
    ```

## Usage

The tool is operated via the command line with various attack modules.

### Quick Start - Automatic Detection

Automatically detect authentication mechanisms used by the target:

```bash
python auth_pwn.py https://example.com --auto-attack
```

### JWT Attacks

**Crack a JWT secret using a wordlist:**
```bash
python auth_pwn.py https://example.com --jwt-crack \
  --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --wordlist /usr/share/wordlists/rockyou.txt
```

**Perform a 'none' algorithm attack:**
```bash
python auth_pwn.py https://example.com --jwt-none \
  --payload '{"user":"admin","isAdmin":true,"role":"administrator"}'
```

**Multi-threaded cracking for faster results:**
```bash
python auth_pwn.py https://example.com --jwt-crack \
  --token "eyJ..." \
  --wordlist rockyou.txt \
  --threads 20
```

### SAML Attacks

**Perform a Signature Exclusion attack:**
```bash
python auth_pwn.py https://example.com --saml-exclude \
  --saml-response "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZ..." \
  --new-user "admin"
```

### OAuth Attacks

**Generate potential redirect URI bypasses:**
```bash
python auth_pwn.py https://example.com --oauth-redirect-bypass \
  --legit-redirect "https://example.com/callback" \
  --attacker-domain "evil.com"
```

## Real-World Examples

### Example 1: Complete JWT Assessment
```bash
# Step 1: Auto-detect mechanisms
python auth_pwn.py https://vulnerable-app.com --auto-attack

# Step 2: If JWT is detected, extract token from browser/Burp
# Step 3: Crack the secret
python auth_pwn.py https://vulnerable-app.com --jwt-crack \
  --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" \
  --wordlist /usr/share/wordlists/rockyou.txt \
  --threads 16

# Step 4: If secret not found, try 'none' algorithm
python auth_pwn.py https://vulnerable-app.com --jwt-none \
  --payload '{"sub":"1234567890","name":"admin","iat":1516239022,"role":"admin"}'
```

### Example 2: OAuth Redirect URI Testing
```bash
# Generate various bypass payloads
python auth_pwn.py https://oauth-provider.com --oauth-redirect-bypass \
  --legit-redirect "https://legitimate-client.com/oauth/callback" \
  --attacker-domain "attacker-controlled.com"

# Test each generated URL manually or with automated tools
```

### Example 3: SAML SSO Bypass
```bash
# Capture SAML response from browser/proxy
# Attempt signature exclusion
python auth_pwn.py https://sso-target.com --saml-exclude \
  --saml-response "PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIC4uLg==" \
  --new-user "administrator"
```

## Command Line Options

```
usage: auth_pwn.py [-h] [--auto-attack] [--threads THREADS] [--jwt-crack] [--jwt-none] [--token TOKEN] [--payload PAYLOAD] [--wordlist WORDLIST] [--saml-exclude] [--saml-response SAML_RESPONSE] [--new-user NEW_USER] [--oauth-redirect-bypass] [--client-id CLIENT_ID] [--legit-redirect LEGIT_REDIRECT] [--attacker-domain ATTACKER_DOMAIN] target

AuthPwn - An Integrated Authentication Attack Framework.

positional arguments:
  target                The target URL to analyze.

optional arguments:
  -h, --help            show this help message and exit
  --auto-attack         Automatically detect authentication mechanisms.
  --threads THREADS     Number of threads for cracking (default: 10)

JWT Attacks:
  --jwt-crack           Crack JWT secret.
  --jwt-none            Perform 'alg:none' attack.
  --token TOKEN         JWT token for cracking.
  --payload PAYLOAD     JSON payload for 'none' attack (e.g., '{"user":"admin"}')
  --wordlist WORDLIST   Path to the wordlist for cracking.

SAML Attacks:
  --saml-exclude        Perform SAML Signature Exclusion attack.
  --saml-response SAML_RESPONSE
                        Base64 encoded SAML response.
  --new-user NEW_USER   The new username/ID to forge in the assertion.

OAuth Attacks:
  --oauth-redirect-bypass
                        Generate redirect_uri bypasses.
  --client-id CLIENT_ID
                        The OAuth client ID.
  --legit-redirect LEGIT_REDIRECT
                        The legitimate redirect_uri.
  --attacker-domain ATTACKER_DOMAIN
                        The attacker's domain for bypasses.
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup
```bash
git clone https://github.com/skypoc/AuthPwn.git
cd AuthPwn
pip install -r requirements.txt

# Run tests
python auth_pwn.py --help

# Test auto-detection
python auth_pwn.py https://httpbin.org --auto-attack
```

### Code Style
- Follow PEP 8 guidelines
- Add type hints where possible
- Include docstrings for new functions
- Test your changes before submitting

## Roadmap

- [ ] JWT Algorithm Confusion attacks (RS256 → HS256)
- [ ] SAML XML Signature Wrapping (XSW) attacks
- [ ] OAuth PKCE bypass techniques
- [ ] Support for additional authentication mechanisms (Kerberos, NTLM)
- [ ] Web interface for easier usage
- [ ] Integration with Burp Suite extensions
- [ ] Docker container support
- [ ] Automated report generation

## Troubleshooting

### Common Issues

**Q: "ModuleNotFoundError" when running the script**
```bash
# Solution: Install dependencies
pip install -r requirements.txt
```

**Q: JWT cracking is slow**
```bash
# Solution: Increase thread count and use smaller wordlists
python auth_pwn.py target --jwt-crack --token "..." --wordlist small-list.txt --threads 20
```

**Q: SAML response parsing fails**
```bash
# Solution: Ensure the SAML response is properly base64 encoded
# Use tools like CyberChef or base64 command to verify encoding
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by the HTB-CWEE guide to attacking authentication mechanisms
- Thanks to the security research community for their valuable insights
- Special thanks to PortSwigger's research on JWT vulnerabilities
- OWASP for their comprehensive authentication testing guidelines

## Responsible Disclosure

If you discover any security vulnerabilities in this tool itself, please report them responsibly by:
1. Opening a GitHub issue with minimal details
2. Contacting the maintainer privately for sensitive issues
3. Allowing reasonable time for fixes before public disclosure

## Legal Notice

This tool is designed for legal security testing and educational purposes only. Users are responsible for ensuring they have proper authorization before testing any systems. The authors are not responsible for any misuse of this tool.

**Always ensure you have explicit written permission before testing any system that you do not own.**
