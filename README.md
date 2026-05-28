# cve_2025_47227
Exploit for CVE-2025-47227 - ScriptCase Password Reset (Pre-Auth)

---

**CVE-2025-47227** is a **pre-auth** authentication bypass (CVSS 9.8) in the ScriptCase Production Environment ≤ 9.12.006. The `login.php` endpoint allows resetting the administrator password without a token, email validation, or authentication—only a 4-letter CAPTCHA (trivial to solve) and a POST with `nm_action=change_pass` are needed.

When chained with **CVE-2025-47228** (authenticated command injection in the SSH tunnel), it results in **RCE without credentials**.

### Execution mode:

```bash
python3 cve_2025_47227.py --target https://tar.get --password 'P@ssw0rd!'
```

