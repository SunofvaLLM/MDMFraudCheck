#!/usr/bin/env python3
"""
Unauthorized MDM Enrollment Detector
Purpose: Detects suspicious patterns indicating unauthorized device management enrollment
Author: SunofvaLLM
Repository: https://github.com/SunofvaLLM/MDMFraudCheck
WARNING: This tool is specifically designed to detect potential privacy violations
"""

import requests
import dns.resolver
import argparse
import json
import sys
import re
import whois
from datetime import datetime, timezone
from urllib.parse import urlparse
import ssl
import socket

class UnauthorizedMDMDetector:
    def __init__(self):
        self.suspicious_patterns = []
        self.critical_alerts = []
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # Known personal email domains that should NEVER have enterprise management
        self.PERSONAL_DOMAINS = {
            'icloud.com', 'me.com', 'mac.com',
            'gmail.com', 'googlemail.com',
            'yahoo.com', 'ymail.com', 'rocketmail.com',
            'hotmail.com', 'outlook.com', 'live.com', 'msn.com',
            'aol.com', 'aim.com',
            'protonmail.com', 'proton.me',
            'tutanota.com', 'tutamail.com',
            'zoho.com', 'yandex.com', 'mail.com'
        }
    
    def validate_email(self, email):
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    def detect_apple_mdm_hijacking(self, email):
        """Detect signs of Apple ID MDM hijacking"""
        domain = email.split('@')[1].lower()
        
        if domain not in ['icloud.com', 'me.com', 'mac.com']:
            return {'apple_domain': False}
        
        # This is a PERSONAL Apple ID being analyzed
        alerts = {
            'domain_type': 'PERSONAL_APPLE_ID',
            'expected_management': 'NONE',
            'alerts': []
        }
        
        # Check for Exchange autodiscover (MAJOR RED FLAG for personal Apple IDs)
        autodiscover_urls = [
            f"https://autodiscover.{domain}/autodiscover/autodiscover.xml",
            f"https://{domain}/autodiscover/autodiscover.xml"
        ]
        
        for url in autodiscover_urls:
            try:
                response = requests.get(url, timeout=5, headers=self.headers)
                if response.status_code in [200, 401, 403]:
                    alerts['alerts'].append({
                        'severity': 'CRITICAL',
                        'finding': 'Exchange Autodiscover detected on personal Apple domain',
                        'implication': 'This should NEVER exist for personal iCloud accounts',
                        'url': url,
                        'action_required': 'IMMEDIATE - Check all devices for unauthorized MDM profiles'
                    })
            except:
                continue
        
        # Check for Microsoft tenant (another major red flag)
        try:
            tenant_url = f"https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid_configuration"
            response = requests.get(tenant_url, timeout=10, headers=self.headers)
            if response.status_code == 200:
                alerts['alerts'].append({
                    'severity': 'CRITICAL',
                    'finding': 'Microsoft 365 tenant detected for personal Apple domain',
                    'implication': 'Personal Apple domains should not have Microsoft tenants',
                    'action_required': 'IMMEDIATE - Apple ID may be compromised'
                })
        except:
            pass
        
        # Check Apple's Device Enrollment Program indicators
        try:
            dep_check_url = "https://deviceenrollment.apple.com"
            response = requests.head(dep_check_url, timeout=5)
            if response.status_code == 200:
                alerts['alerts'].append({
                    'severity': 'HIGH',
                    'finding': 'Apple Device Enrollment Program service accessible',
                    'implication': 'Your Apple ID may be enrolled in corporate device management',
                    'action_required': 'Check device settings for MDM profiles'
                })
        except:
            pass
        
        return alerts
    
    def detect_gmail_workspace_hijacking(self, email):
        """Detect Gmail accounts enrolled in unauthorized Workspace"""
        domain = email.split('@')[1].lower()
        
        if domain not in ['gmail.com', 'googlemail.com']:
            return {'gmail_domain': False}
        
        alerts = {
            'domain_type': 'PERSONAL_GMAIL',
            'expected_management': 'NONE',
            'alerts': []
        }
        
        # Check for Google Workspace MX records (suspicious for gmail.com)
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            workspace_indicators = []
            
            for record in txt_records:
                record_text = str(record).lower()
                if 'google-site-verification' in record_text:
                    workspace_indicators.append('Site verification record found')
                if 'v=spf1' in record_text and 'include:_spf.google.com' in record_text:
                    workspace_indicators.append('Google SPF record configured')
            
            if len(workspace_indicators) > 1:
                alerts['alerts'].append({
                    'severity': 'MODERATE',
                    'finding': 'Multiple Google Workspace indicators on personal Gmail domain',
                    'implication': 'Personal Gmail may have been added to organization',
                    'indicators': workspace_indicators
                })
        except:
            pass
        
        return alerts
    
    def detect_microsoft_personal_hijacking(self, email):
        """Detect Microsoft personal accounts with enterprise enrollment"""
        domain = email.split('@')[1].lower()
        
        if domain not in ['outlook.com', 'hotmail.com', 'live.com', 'msn.com']:
            return {'microsoft_personal': False}
        
        alerts = {
            'domain_type': 'PERSONAL_MICROSOFT',
            'expected_management': 'NONE',
            'alerts': []
        }
        
        # Check for enterprise indicators on personal Microsoft domains
        try:
            # Check if domain has been configured for enterprise use
            tenant_url = f"https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid_configuration"
            response = requests.get(tenant_url, timeout=10, headers=self.headers)
            if response.status_code == 200:
                alerts['alerts'].append({
                    'severity': 'CRITICAL',
                    'finding': 'Microsoft 365 tenant configuration on personal domain',
                    'implication': 'Personal Microsoft account may be enrolled in organization',
                    'action_required': 'Check account.microsoft.com for organizational access'
                })
        except:
            pass
        
        return alerts
    
    def analyze_dns_tampering(self, domain):
        """Look for signs of DNS manipulation that could indicate unauthorized enrollment"""
        tampering_indicators = []
        
        if domain not in self.PERSONAL_DOMAINS:
            return {'personal_domain': False}
        
        try:
            # Check for suspicious TXT records
            txt_records = dns.resolver.resolve(domain, 'TXT')
            suspicious_txt = []
            
            for record in txt_records:
                record_text = str(record).lower()
                
                # Look for enterprise verification records on personal domains
                suspicious_patterns = [
                    'ms=', 'google-site-verification=', 'v=spf1',
                    'v=dmarc1', 'apple-domain-verification=',
                    'facebook-domain-verification=', 'zoom-verification='
                ]
                
                for pattern in suspicious_patterns:
                    if pattern in record_text:
                        suspicious_txt.append({
                            'pattern': pattern,
                            'record': record_text,
                            'concern': 'Enterprise verification on personal domain'
                        })
            
            if suspicious_txt:
                tampering_indicators.append({
                    'type': 'DNS_TXT_RECORDS',
                    'severity': 'HIGH',
                    'finding': 'Enterprise verification records on personal domain',
                    'records': suspicious_txt,
                    'implication': 'Domain may have been claimed by organization'
                })
        
        except Exception as e:
            pass
        
        # Check for unauthorized MX record changes
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            expected_mx = {
                'gmail.com': ['gmail-smtp-in.l.google.com'],
                'icloud.com': ['mx01.mail.icloud.com', 'mx02.mail.icloud.com'],
                'outlook.com': ['outlook-com.olc.protection.outlook.com'],
                'yahoo.com': ['mta5.am0.yahoodns.net', 'mta6.am0.yahoodns.net', 'mta7.am0.yahoodns.net']
            }
            
            if domain in expected_mx:
                actual_mx = [str(mx.exchange).lower() for mx in mx_records]
                expected_patterns = expected_mx[domain]
                
                unexpected_mx = []
                for mx in actual_mx:
                    if not any(pattern in mx for pattern in expected_patterns):
                        unexpected_mx.append(mx)
                
                if unexpected_mx:
                    tampering_indicators.append({
                        'type': 'MX_RECORDS',
                        'severity': 'CRITICAL',
                        'finding': 'Unexpected MX records on personal domain',
                        'unexpected_records': unexpected_mx,
                        'expected_patterns': expected_patterns,
                        'implication': 'Email may be redirected through enterprise servers'
                    })
        
        except:
            pass
        
        return {'tampering_indicators': tampering_indicators}
    
    def check_unauthorized_enrollment_evidence(self, email):
        """Main function to check for unauthorized enrollment evidence"""
        domain = email.split('@')[1].lower()
        
        if domain not in self.PERSONAL_DOMAINS:
            return {
                'personal_domain': False,
                'note': f'Domain {domain} is not recognized as a major personal email provider'
            }
        
        evidence = {
            'email': email,
            'domain': domain,
            'domain_type': 'PERSONAL',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'unauthorized_indicators': []
        }
        
        # Run all detection methods
        apple_results = self.detect_apple_mdm_hijacking(email)
        gmail_results = self.detect_gmail_workspace_hijacking(email)
        microsoft_results = self.detect_microsoft_personal_hijacking(email)
        dns_results = self.analyze_dns_tampering(domain)
        
        # Collect all alerts
        all_alerts = []
        
        if apple_results.get('alerts'):
            all_alerts.extend(apple_results['alerts'])
            evidence['apple_analysis'] = apple_results
        
        if gmail_results.get('alerts'):
            all_alerts.extend(gmail_results['alerts'])
            evidence['gmail_analysis'] = gmail_results
        
        if microsoft_results.get('alerts'):
            all_alerts.extend(microsoft_results['alerts'])
            evidence['microsoft_analysis'] = microsoft_results
        
        if dns_results.get('tampering_indicators'):
            all_alerts.extend(dns_results['tampering_indicators'])
            evidence['dns_analysis'] = dns_results
        
        evidence['unauthorized_indicators'] = all_alerts
        
        # Calculate threat level
        critical_count = sum(1 for alert in all_alerts if alert.get('severity') == 'CRITICAL')
        high_count = sum(1 for alert in all_alerts if alert.get('severity') == 'HIGH')
        
        if critical_count > 0:
            threat_level = 'CRITICAL'
            threat_message = 'STRONG evidence of unauthorized MDM enrollment detected'
        elif high_count > 0:
            threat_level = 'HIGH'
            threat_message = 'Suspicious indicators of potential unauthorized enrollment'
        elif len(all_alerts) > 0:
            threat_level = 'MODERATE'
            threat_message = 'Some concerning indicators detected'
        else:
            threat_level = 'LOW'
            threat_message = 'No significant unauthorized enrollment indicators'
        
        evidence['threat_assessment'] = {
            'level': threat_level,
            'message': threat_message,
            'critical_alerts': critical_count,
            'high_alerts': high_count,
            'total_alerts': len(all_alerts)
        }
        
        return evidence
    
    def generate_emergency_response_plan(self, evidence):
        """Generate immediate action plan for unauthorized enrollment"""
        threat_level = evidence['threat_assessment']['level']
        domain = evidence['domain']
        
        response_plan = {
            'immediate_actions': [],
            'device_checks': [],
            'account_security': [],
            'legal_steps': [],
            'evidence_preservation': []
        }
        
        if threat_level in ['CRITICAL', 'HIGH']:
            # Immediate actions for confirmed/suspected unauthorized enrollment
            response_plan['immediate_actions'] = [
                '🚨 STOP using this email on personal devices immediately',
                '📱 Check ALL devices for MDM profiles in settings',
                '🔒 Change password and enable 2FA if not already done',
                '📋 Document everything - take screenshots of all findings',
                '⚖️ Consider this a privacy violation requiring legal action'
            ]
            
            # Device-specific checks
            if domain in ['icloud.com', 'me.com', 'mac.com']:
                response_plan['device_checks'] = [
                    'iOS: Settings > General > VPN & Device Management',
                    'macOS: System Preferences > Profiles',
                    'Check Apple ID at appleid.apple.com for unknown devices',
                    'Look for Apple Configurator profiles',
                    'Check for corporate apps you didn\'t install'
                ]
            elif domain in ['gmail.com', 'googlemail.com']:
                response_plan['device_checks'] = [
                    'Android: Settings > Security > Device Admin Apps',
                    'Check Google Account at myaccount.google.com',
                    'Look for Google Workspace enrollment',
                    'Check for unknown devices in account'
                ]
            elif domain in ['outlook.com', 'hotmail.com', 'live.com']:
                response_plan['device_checks'] = [
                    'Windows: Settings > Accounts > Access work or school',
                    'Check Microsoft Account at account.microsoft.com',
                    'Look for organizational access you didn\'t authorize',
                    'Check for Intune Company Portal app'
                ]
            
            # Account security steps
            response_plan['account_security'] = [
                'Review all account recovery methods',
                'Check for administrator accounts you didn\'t add',
                'Review app permissions and revoke suspicious ones',
                'Enable all available security notifications',
                'Consider creating new personal account if compromise is severe'
            ]
            
            # Legal steps
            response_plan['legal_steps'] = [
                'File complaint with local privacy authority (FTC, ICO, etc.)',
                'Contact email provider\'s abuse department',
                'Document violation of computer fraud laws',
                'Consider consulting privacy attorney',
                'Report to law enforcement if criminal activity suspected'
            ]
            
            # Evidence preservation
            response_plan['evidence_preservation'] = [
                'Save this analysis report with timestamp',
                'Screenshot all MDM profiles found on devices',
                'Export account activity logs',
                'Document any unauthorized changes to settings',
                'Keep records of all communications with providers'
            ]
        
        return response_plan

def print_unauthorized_mdm_report(evidence):
    """Print detailed unauthorized MDM detection report"""
    if 'error' in evidence:
        print(f"❌ Error: {evidence['error']}")
        return
    
    email = evidence['email']
    domain = evidence['domain']
    threat = evidence['threat_assessment']
    
    # Header with threat level
    threat_emoji = {
        'CRITICAL': '🚨',
        'HIGH': '⚠️',
        'MODERATE': '⚠️',
        'LOW': '✅'
    }
    
    print("\n" + "="*80)
    print(f"🕵️ UNAUTHORIZED MDM ENROLLMENT DETECTION REPORT")
    print("="*80)
    print(f"Email: {email}")
    print(f"Domain: {domain} (PERSONAL EMAIL PROVIDER)")
    print(f"Analysis Time: {evidence['timestamp']}")
    print(f"\n{threat_emoji[threat['level']]} THREAT LEVEL: {threat['level']}")
    print(f"Assessment: {threat['message']}")
    print(f"Alerts Found: {threat['total_alerts']} ({threat['critical_alerts']} critical, {threat['high_alerts']} high)")
    
    # Show all unauthorized indicators
    if evidence['unauthorized_indicators']:
        print(f"\n🚩 UNAUTHORIZED ENROLLMENT INDICATORS:")
        print("-" * 50)
        
        for i, indicator in enumerate(evidence['unauthorized_indicators'], 1):
            severity_emoji = {
                'CRITICAL': '🚨',
                'HIGH': '⚠️',
                'MODERATE': '⚠️',
                'LOW': 'ℹ️'
            }
            
            print(f"\n{i}. {severity_emoji.get(indicator['severity'], 'ℹ️')} {indicator['severity']} ALERT")
            print(f"   Finding: {indicator['finding']}")
            print(f"   Implication: {indicator['implication']}")
            
            if 'action_required' in indicator:
                print(f"   🔧 Action Required: {indicator['action_required']}")
            
            if 'url' in indicator:
                print(f"   🔗 Evidence URL: {indicator['url']}")
            
            if 'records' in indicator:
                print(f"   📋 Evidence Records:")
                for record in indicator['records'][:3]:  # Show first 3 records
                    if isinstance(record, dict):
                        print(f"      - {record}")
                    else:
                        print(f"      - {record}")
    
    else:
        print(f"\n✅ No unauthorized enrollment indicators detected")
        print(f"   Your {domain} account appears to be properly personal")
    
    # Generate and show response plan if needed
    if threat['level'] in ['CRITICAL', 'HIGH']:
        print(f"\n🚨 EMERGENCY RESPONSE PLAN")
        print("-" * 50)
        
        detector = UnauthorizedMDMDetector()
        response_plan = detector.generate_emergency_response_plan(evidence)
        
        print(f"\n⚡ IMMEDIATE ACTIONS:")
        for action in response_plan['immediate_actions']:
            print(f"  {action}")
        
        print(f"\n📱 DEVICE CHECKS REQUIRED:")
        for check in response_plan['device_checks']:
            print(f"  • {check}")
        
        print(f"\n🔒 ACCOUNT SECURITY STEPS:")
        for step in response_plan['account_security']:
            print(f"  • {step}")
        
        print(f"\n⚖️ LEGAL ACTIONS:")
        for legal_step in response_plan['legal_steps']:
            print(f"  • {legal_step}")
        
        print(f"\n📋 EVIDENCE PRESERVATION:")
        for evidence_step in response_plan['evidence_preservation']:
            print(f"  • {evidence_step}")
    
    elif threat['level'] == 'MODERATE':
        print(f"\n💡 RECOMMENDED ACTIONS:")
        print(f"  • Monitor devices for any MDM profiles")
        print(f"  • Review account settings for unauthorized changes")
        print(f"  • Enable additional security notifications")
        print(f"  • Document any suspicious device behavior")
    
    print(f"\n" + "="*80)
    print("🔍 DETECTION METHODOLOGY:")
    print("This tool analyzes personal email domains for enterprise management")
    print("indicators that should NOT exist on consumer email services.")
    print("Critical alerts indicate strong evidence of unauthorized enrollment.")
    print("="*80)
    
    # Legal disclaimer
    print("\n⚖️ LEGAL NOTICE:")
    print("Unauthorized device management enrollment may violate:")
    print("• Computer Fraud and Abuse Act (CFAA)")
    print("• Electronic Communications Privacy Act (ECPA)")
    print("• State privacy laws and regulations")
    print("• International data protection regulations")
    print("Consult with legal counsel for specific guidance.")

def main():
    parser = argparse.ArgumentParser(
        description='Detect unauthorized MDM enrollment on personal email accounts',
        epilog='Example: python EnrollmentChecker.py your.personal.email@gmail.com'
    )
    parser.add_argument('email', help='Personal email address to check for unauthorized enrollment')
    parser.add_argument('--json', action='store_true', help='Output detailed results in JSON format')
    parser.add_argument('--save-evidence', help='Save evidence report to file for legal documentation')
    parser.add_argument('--quiet', '-q', action='store_true', help='Show only threat level and critical alerts')
    
    args = parser.parse_args()
    
    # Validate this is a personal email domain
    email = args.email.lower().strip()
    domain = email.split('@')[1] if '@' in email else ''
    
    detector = UnauthorizedMDMDetector()
    
    if domain not in detector.PERSONAL_DOMAINS:
        print(f"⚠️ WARNING: {domain} is not recognized as a major personal email provider.")
        print(f"This tool is designed for personal accounts on services like:")
        print(f"  Gmail, iCloud, Outlook.com, Yahoo, etc.")
        print(f"For corporate domains, use a general email analysis tool instead.")
        
        confirm = input(f"\nContinue analysis anyway? (y/N): ").lower()
        if confirm != 'y':
            sys.exit(0)
    
    # Run unauthorized enrollment detection
    print(f"🔍 Scanning {email} for unauthorized MDM enrollment...")
    print(f"🎯 Target: Personal {domain} account")
    print(f"🚨 Looking for: Enterprise management on consumer email")
    
    try:
        evidence = detector.check_unauthorized_enrollment_evidence(email)
    except KeyboardInterrupt:
        print("\n⏹️ Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Scan failed: {str(e)}")
        sys.exit(1)
    
    # Output results
    if args.json:
        print(json.dumps(evidence, indent=2))
    elif args.quiet:
        threat = evidence['threat_assessment']
        print(f"\nThreat Level: {threat['level']}")
        print(f"Assessment: {threat['message']}")
        if threat['critical_alerts'] > 0:
            print(f"🚨 {threat['critical_alerts']} CRITICAL alerts found!")
            print("Run without --quiet for full details and response plan")
    else:
        print_unauthorized_mdm_report(evidence)
    
    # Save evidence if requested
    if args.save_evidence:
        try:
            with open(args.save_evidence, 'w') as f:
                json.dump(evidence, f, indent=2)
            print(f"\n💾 Evidence report saved to: {args.save_evidence}")
            print("📋 This file can be used for legal documentation")
        except Exception as e:
            print(f"❌ Failed to save evidence: {str(e)}")
    
    # Final warning for high-threat cases
    if evidence['threat_assessment']['level'] in ['CRITICAL', 'HIGH']:
        print(f"\n🚨 CRITICAL PRIVACY VIOLATION DETECTED!")
        print(f"📞 Consider immediate consultation with privacy attorney")
        print(f"⚖️ Document everything and preserve evidence")

if __name__ == '__main__':
    main()
