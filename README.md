# سياج — Siyaj SecureConfig Auditor v1.0

أداة تدقيق أمني لخوادم Linux مبنية بـ Python، تفحص إعدادات SSH والجدار الناري والمستخدمين وفق معايير CIS Benchmarks وتُصدر تقريراً مُرقَّماً.

---
## Demo

![Siyaj Demo](demo.png)
<img width="541" height="631" alt="demo png" src="https://github.com/user-attachments/assets/aaa6238a-3a73-4c58-9fc2-851d110f9d5a" />


## المميزات

- **Non-destructive** — read-only; no configuration is modified
- **Rule-based** — all rules are defined in `cis_rules.json`, separate from the code
- **Modular** — each audit domain is an independent Python module
- **Weighted scoring** — SSH 40% · Firewall 35% · Users 25%
- **Report export** — JSON or TXT

---

## متطلبات التشغيل

| Requirement | Version |
|-------------|---------|
| Python | 3.8+ |
| colorama | 0.4.6+ |
| OS | Linux (Ubuntu / Debian / Kali) |
| Privileges | sudo (required to read `/etc/shadow` and sudoers) |

---

## التثبيت

```bash
git clone https://github.com/your-username/siyaj.git
cd siyaj
pip install -r requirements.txt
```

---

## الاستخدام

```bash
# Full audit
sudo python3 main.py --audit all

# SSH only
sudo python3 main.py --audit ssh

# Firewall only
sudo python3 main.py --audit firewall

# Users only
sudo python3 main.py --audit users

# Full audit with JSON export
sudo python3 main.py --audit all --output json

# Full audit with TXT export
sudo python3 main.py --audit all --output txt
```

---

## مستويات الدرجات

| Score Range | Status |
|-------------|--------|
| 80 – 100 | **Good** — server is well hardened |
| 60 – 79 | **Needs Improvement** — vulnerabilities present that require attention |
| 40 – 59 | **Danger** — high-risk state requiring immediate action |
| 0 – 39 | **Critical** — server is critically exposed |

---

## هيكل المشروع

```
siyaj/
├── main.py            # entry point and argparse
├── ssh_audit.py       # audits /etc/ssh/sshd_config
├── firewall_audit.py  # audits UFW status and dangerous ports
├── users_audit.py     # audits users, root account, and sudo rules
├── scoring.py         # weighted score calculation
├── ui.py              # colored terminal interface
├── exporter.py        # JSON and TXT report export
├── cis_rules.json     # CIS Benchmarks rule definitions
├── requirements.txt   # required packages
└── README.md
```

---

## SSH Checks (8 settings)

| Setting | Expected Value | Weight |
|---------|----------------|--------|
| PermitRootLogin | no | 15 |
| PasswordAuthentication | no | 15 |
| Protocol | 2 | 10 |
| X11Forwarding | no | 5 |
| MaxAuthTries | ≤ 4 | 5 |
| IgnoreRhosts | yes | 5 |
| HostbasedAuthentication | no | 5 |
| PermitEmptyPasswords | no | 5 |

---

## Firewall Checks

| Check | Expected |
|-------|----------|
| UFW Status | active |
| Default Incoming | deny |
| Dangerous Ports | 21, 23, 135, 139, 445, 512, 513, 514, 3389, 5900 must be closed |

---

## Users Checks

| Check | Expected |
|-------|----------|
| Root Account | locked |
| UID=0 Accounts | root only — no other account should have UID=0 |
| Empty Passwords | no accounts with an empty password |
| Sudoers | no NOPASSWD rules present |

---

## مثال على الإخراج

```
  ███████╗██╗██╗   ██╗ █████╗      ██╗
  ██╔════╝██║╚██╗ ██╔╝██╔══██╗     ██║
  ███████╗██║ ╚████╔╝ ███████║     ██║
  ╚════██║██║  ╚██╔╝  ██╔══██║██   ██║
  ███████║██║   ██║   ██║  ██║╚█████╔╝
  ╚══════╝╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚════╝
        سياج — SecureConfig Auditor v1.0

[*] SSH Audit (/etc/ssh/sshd_config)
----------------------------------------------------
  [PASS] PermitRootLogin        : no
  [PASS] PasswordAuthentication : no
  [PASS] Protocol               : 2
  [PASS] X11Forwarding          : no
  [PASS] MaxAuthTries           : 3
  [PASS] IgnoreRhosts           : yes
  [PASS] HostbasedAuthentication: no
  [PASS] PermitEmptyPasswords   : no

[*] Firewall Audit (UFW)
----------------------------------------------------
  [PASS] UFW Status      : active
  [PASS] Default Incoming: deny
  [PASS] Dangerous Ports : all closed (21, 23, 135, 139, 445, 512, 513, 514, 3389, 5900)

[*] Users Audit
----------------------------------------------------
  [PASS] Root Account  : locked
  [PASS] UID=0 Accounts: root only
  [PASS] Empty Passwords: none found
  [PASS] NOPASSWD Rules : none found

[*] Score Summary
----------------------------------------------------
  SSH:      65/65  (100.0%)
  FIREWALL: 35/35  (100.0%)
  USERS:    25/25  (100.0%)

==================================================
  FINAL SECURITY SCORE
==================================================
    100.0 / 100  —  Good
==================================================
```

---

## الترخيص

MIT License — for academic, research, and defensive use only.
