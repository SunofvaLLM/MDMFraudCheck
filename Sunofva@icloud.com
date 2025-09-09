
~/MDMFraudCheck $ python EnrollmentCheck.py sunofva@icloud.com

UNAUTHORIZED MDM ENROLLMENT DETECTION REPORT
======================================================================
Email: sunofva@icloud.com
Domain: icloud.com
Analysis Time: 2025-09-09T04:37:53.354257+00:00
Threat Level: CRITICAL
Total Alerts: 4 (Critical: 1, High: 3)

Alerts:
1. Severity: CRITICAL
   Finding: Exchange Autodiscover detected
   URL: https://icloud.com/autodiscover/autodiscover.xml
   Implication: Personal Apple ID should never have Autodiscover
   Action Required: Check all devices for unauthorized MDM profiles
2. Severity: HIGH
   Finding: DNS TXT contains google-site-verification=
   Implication: Enterprise verification record found on personal domain
   Record: "google-site-verification=Ik3jMkCjHnUgyIoFR0Kw74srr0H5ynFmUk8fyY1uBck"
3. Severity: HIGH
   Finding: DNS TXT contains google-site-verification=
   Implication: Enterprise verification record found on personal domain
   Record: "google-site-verification=knAEOH4QxR29I4gjRkpkvmUmP2AA7WrDk8Kq0wu9g9o"
4. Severity: HIGH
   Finding: DNS TXT contains v=spf1
   Implication: Enterprise verification record found on personal domain
   Record: "v=spf1 ip4:17.41.0.0/16 ip4:17.58.0.0/16 ip4:17.142.0.0/15 ip4:17.57.155.0/24 ip4:17.57.156.0/24 ip4:144.178.36.0/24 ip4:144.178.38.0/24 ip4:112.19.199.64/29 ip4:112.19.242.64/29 ip4:222.73.195.64/29 ip4:157.255.1.64/29" " ip4:106.39.212.64/29 ip4:123.126.78.64/29 ip4:183.240.219.64/29 ip4:39.156.163.64/29 ip4:57.103.64.0/18" " ip6:2a01:b747:3000:200::/56 ip6:2a01:b747:3001:200::/56 ip6:2a01:b747:3002:200::/56 ip6:2a01:b747:3003:200::/56 ip6:2a01:b747:3004:200::/56 ip6:2a01:b747:3005:200::/56 ip6:2a01:b747:3006:200::/56 ~all"

Emergency Response Plan:

Immediate Actions:
 - STOP using this email on personal devices immediately
 - Check ALL devices for MDM profiles in settings
 - Change password and enable 2FA if not already done
 - Document all findings
 - Consider legal consultation

Device Checks:
 - iOS: Settings > General > VPN & Device Management
 - macOS: System Preferences > Profiles
 - Check Apple ID at appleid.apple.com for unknown devices

Account Security:
 - Review recovery methods
 - Check for unauthorized apps or admin accounts
 - Enable security notifications

Legal Steps:
 - File complaint with privacy authority
 - Contact email provider abuse department
 - Document all findings for legal purposes

Evidence Preservation:
 - Save analysis report with timestamp
 - Screenshot all MDM profiles
 - Export account activity logs
~/MDMFraudCheck $
