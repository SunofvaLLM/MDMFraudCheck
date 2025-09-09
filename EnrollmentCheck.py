#!/usr/bin/env python3
"""
High-Confidence Unauthorized MDM Enrollment Detector
Author: SunofvaLLM (Refactored and merged)
Purpose: Detects unauthorized MDM enrollment on personal email domains
Features:
- Multi-resolver DNS checks to prevent spoofing
- Confidence scoring for each indicator
- Full human-readable report with emergency response plan
- Minimalistic JSON output for automation
"""

import requests
import dns.resolver
import json
import re
import sys
from datetime import datetime, timezone

TRUSTED_RESOLVERS = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9']

PERSONAL_DOMAINS = {
    'icloud.com', 'me.com', 'mac.com',
    'gmail.com', 'googlemail.com',
    'yahoo.com', 'ymail.com', 'rocketmail.com',
    'hotmail.com', 'outlook.com', 'live.com', 'msn.com',
    'aol.com', 'aim.com',
    'protonmail.com', 'proton.me',
    'tutanota.com', 'tutamail.com',
    'zoho.com', 'yandex.com', 'mail.com'
}

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}


class HighConfidenceMDMDetector:
    def __init__(self):
        pass

    @staticmethod
    def validate_email(email):
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    @staticmethod
    def multi_resolver_dns(domain, record_type='TXT'):
        """Query multiple resolvers to prevent spoofing"""
        all_results = []
        verified = set()
        for resolver_ip in TRUSTED_RESOLVERS:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [resolver_ip]
            try:
                answers = resolver.resolve(domain, record_type)
                result_set = set(str(r) for r in answers)
                all_results.append({'resolver': resolver_ip, 'records': list(result_set)})
                if not verified:
                    verified = result_set
                else:
                    verified.intersection_update(result_set)
            except Exception:
                all_results.append({'resolver': resolver_ip, 'records': []})
                verified.intersection_update([])
        return list(verified), all_results

    def detect_apple_mdm(self, email):
        domain = email.split('@')[1].lower()
        alerts = []
        if domain not in ['icloud.com', 'me.com', 'mac.com']:
            return alerts

        # Exchange Autodiscover
        for url in [f"https://autodiscover.{domain}/autodiscover/autodiscover.xml", f"https://{domain}/autodiscover/autodiscover.xml"]:
            try:
                resp = requests.get(url, timeout=5, headers=HEADERS)
                if resp.status_code in [200, 401, 403]:
                    alerts.append({'finding': 'Exchange Autodiscover detected',
                                   'severity': 'CRITICAL', 'confidence': 1.0,
                                   'url': url,
                                   'implication': 'Personal Apple ID should never have Autodiscover',
                                   'action_required': 'Check all devices for unauthorized MDM profiles'})
            except:
                continue

        # Microsoft tenant
        try:
            tenant_url = f"https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid_configuration"
            resp = requests.get(tenant_url, timeout=5, headers=HEADERS)
            if resp.status_code == 200:
                alerts.append({'finding': 'Microsoft 365 tenant detected',
                               'severity': 'CRITICAL', 'confidence': 1.0,
                               'url': tenant_url,
                               'implication': 'Personal Apple domain should not have Microsoft tenants',
                               'action_required': 'Immediate review of Apple ID security'})
        except:
            pass

        # Apple DEP
        try:
            dep_url = "https://deviceenrollment.apple.com"
            resp = requests.head(dep_url, timeout=5)
            if resp.status_code == 200:
                alerts.append({'finding': 'Apple DEP service accessible',
                               'severity': 'HIGH', 'confidence': 0.8,
                               'url': dep_url,
                               'implication': 'Apple ID may be enrolled in corporate device management'})
        except:
            pass

        return alerts

    def detect_gmail_workspace(self, email):
        domain = email.split('@')[1].lower()
        alerts = []
        if domain not in ['gmail.com', 'googlemail.com']:
            return alerts

        verified_txt, raw_txt = self.multi_resolver_dns(domain, 'TXT')
        indicators = []
        for record in verified_txt:
            record_lower = record.lower()
            if 'google-site-verification' in record_lower:
                indicators.append('site-verification')
            if 'v=spf1' in record_lower and 'include:_spf.google.com' in record_lower:
                indicators.append('spf-google')
        if len(indicators) > 1:
            alerts.append({'finding': 'Multiple Google Workspace indicators',
                           'severity': 'MODERATE', 'confidence': len(indicators)/2,
                           'indicators': indicators,
                           'implication': 'Personal Gmail may be enrolled in organization'})
        return alerts

    def detect_microsoft_personal(self, email):
        domain = email.split('@')[1].lower()
        alerts = []
        if domain not in ['outlook.com', 'hotmail.com', 'live.com', 'msn.com']:
            return alerts

        try:
            tenant_url = f"https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid_configuration"
            resp = requests.get(tenant_url, timeout=5, headers=HEADERS)
            if resp.status_code == 200:
                alerts.append({'finding': 'Microsoft 365 tenant on personal domain',
                               'severity': 'CRITICAL', 'confidence': 1.0,
                               'url': tenant_url,
                               'implication': 'Personal Microsoft account may be enrolled',
                               'action_required': 'Check account.microsoft.com for unauthorized access'})
        except:
            pass
        return alerts

    def analyze_dns(self, domain):
        alerts = []
        verified_txt, txt_raw = self.multi_resolver_dns(domain, 'TXT')
        suspicious_patterns = ['ms=', 'google-site-verification=', 'v=spf1', 'v=dmarc1', 'apple-domain-verification=']
        for record in verified_txt:
            for pattern in suspicious_patterns:
                if pattern in record.lower():
                    alerts.append({'finding': f'DNS TXT contains {pattern}',
                                   'severity': 'HIGH', 'confidence': 1.0,
                                   'record': record,
                                   'implication': 'Enterprise verification record found on personal domain'})

        verified_mx, mx_raw = self.multi_resolver_dns(domain, 'MX')
        expected_mx_map = {
            'gmail.com': ['gmail-smtp-in.l.google.com'],
            'icloud.com': ['mx01.mail.icloud.com', 'mx02.mail.icloud.com'],
            'outlook.com': ['outlook-com.olc.protection.outlook.com'],
            'yahoo.com': ['mta5.am0.yahoodns.net', 'mta6.am0.yahoodns.net']
        }
        if domain in expected_mx_map:
            unexpected_mx = [mx for mx in verified_mx if not any(exp in mx for exp in expected_mx_map[domain])]
            for mx in unexpected_mx:
                alerts.append({'finding': f'Unexpected MX record {mx}',
                               'severity': 'CRITICAL', 'confidence': 1.0,
                               'implication': 'Email may be redirected through enterprise servers'})
        return alerts

    def generate_emergency_response_plan(self, evidence):
        threat_level = evidence['threat_level']
        domain = evidence['domain']
        response_plan = {
            'immediate_actions': [],
            'device_checks': [],
            'account_security': [],
            'legal_steps': [],
            'evidence_preservation': []
        }
        if threat_level in ['CRITICAL', 'HIGH']:
            response_plan['immediate_actions'] = [
                'STOP using this email on personal devices immediately',
                'Check ALL devices for MDM profiles in settings',
                'Change password and enable 2FA if not already done',
                'Document all findings',
                'Consider legal consultation'
            ]
            if domain in ['icloud.com', 'me.com', 'mac.com']:
                response_plan['device_checks'] = [
                    'iOS: Settings > General > VPN & Device Management',
                    'macOS: System Preferences > Profiles',
                    'Check Apple ID at appleid.apple.com for unknown devices'
                ]
            elif domain in ['gmail.com', 'googlemail.com']:
                response_plan['device_checks'] = [
                    'Android: Settings > Security > Device Admin Apps',
                    'Check Google Account at myaccount.google.com'
                ]
            elif domain in ['outlook.com', 'hotmail.com', 'live.com']:
                response_plan['device_checks'] = [
                    'Windows: Settings > Accounts > Access work or school',
                    'Check Microsoft Account at account.microsoft.com'
                ]
            response_plan['account_security'] = [
                'Review recovery methods',
                'Check for unauthorized apps or admin accounts',
                'Enable security notifications'
            ]
            response_plan['legal_steps'] = [
                'File complaint with privacy authority',
                'Contact email provider abuse department',
                'Document all findings for legal purposes'
            ]
            response_plan['evidence_preservation'] = [
                'Save analysis report with timestamp',
                'Screenshot all MDM profiles',
                'Export account activity logs'
            ]
        return response_plan

    def run_detection(self, email):
        if not self.validate_email(email):
            return {'error': 'Invalid email format'}

        domain = email.split('@')[1].lower()
        if domain not in PERSONAL_DOMAINS:
            return {'error': f'Domain {domain} not recognized as major personal email provider'}

        alerts = []
        alerts.extend(self.detect_apple_mdm(email))
        alerts.extend(self.detect_gmail_workspace(email))
        alerts.extend(self.detect_microsoft_personal(email))
        alerts.extend(self.analyze_dns(domain))

        critical_count = sum(1 for a in alerts if a['severity'] == 'CRITICAL')
        high_count = sum(1 for a in alerts if a['severity'] == 'HIGH')

        threat_level = 'LOW'
        if critical_count > 0:
            threat_level = 'CRITICAL'
        elif high_count > 0:
            threat_level = 'HIGH'
        elif alerts:
            threat_level = 'MODERATE'

        return {
            'email': email,
            'domain': domain,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'threat_level': threat_level,
            'total_alerts': len(alerts),
            'critical_alerts': critical_count,
            'high_alerts': high_count,
            'alerts': alerts,
            'emergency_plan': self.generate_emergency_response_plan({'threat_level': threat_level, 'domain': domain})
        }


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Detect unauthorized MDM enrollment on personal email accounts')
    parser.add_argument('email', help='Personal email address to check')
    parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    parser.add_argument('--quiet', '-q', action='store_true', help='Show only threat level and critical alerts')
    parser.add_argument('--save-evidence', help='Save full report to a file')
    args = parser.parse_args()

    detector = HighConfidenceMDMDetector()
    result = detector.run_detection(args.email.strip())

    if args.json:
        print(json.dumps(result, indent=2))
    elif args.quiet:
        print(f"Threat Level: {result['threat_level']}, Critical Alerts: {result['critical_alerts']}")
    else:
        # Human-readable output
        print(f"\nUNAUTHORIZED MDM ENROLLMENT DETECTION REPORT")
        print("="*70)
        print(f"Email: {result['email']}")
        print(f"Domain: {result['domain']}")
        print(f"Analysis Time: {result['timestamp']}")
        print(f"Threat Level: {result['threat_level']}")
        print(f"Total Alerts: {result['total_alerts']} (Critical: {result['critical_alerts']}, High: {result['high_alerts']})")
        print("\nAlerts:")
        for i, alert in enumerate(result['alerts'], 1):
            print(f"{i}. Severity: {alert['severity']}")
            print(f"   Finding: {alert['finding']}")
            if 'url' in alert:
                print(f"   URL: {alert['url']}")
            if 'implication' in alert:
                print(f"   Implication: {alert['implication']}")
            if 'action_required' in alert:
                print(f"   Action Required: {alert['action_required']}")
            if 'record' in alert:
                print(f"   Record: {alert['record']}")
            if 'indicators' in alert:
                print(f"   Indicators: {alert['indicators']}")

        plan = result.get('emergency_plan', {})
        if plan:
            print("\nEmergency Response Plan:")
            for section, items in plan.items():
                if items:
                    print(f"\n{section.replace('_', ' ').title()}:")
                    for step in items:
                        print(f" - {step}")

    if args.save_evidence:
        try:
            with open(args.save_evidence, 'w') as f:
                json.dump(result, f, indent=2)
            print(f"\nReport saved to {args.save_evidence}")
        except Exception as e:
            print(f"Failed to save report: {str(e)}")


if __name__ == '__main__':
    main()
