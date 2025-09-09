# MDMFraudCheck

🚨 **A specialized tool for detecting unauthorized Mobile Device Management (MDM) enrollment on personal email accounts**

## ⚠️ **CRITICAL PURPOSE**

This tool is designed to help users detect when their **personal email accounts** have been enrolled in organizational device management **without their knowledge or consent**. This is a serious privacy violation that can give organizations control over your personal devices.

## 🎯 **What This Tool Detects**

### **Unauthorized Enrollment Patterns:**
- Personal Apple IDs enrolled in corporate MDM programs
- Gmail accounts added to unauthorized Google Workspace organizations  
- Personal Microsoft accounts enrolled in Intune management
- DNS tampering on personal email domains
- Enterprise security configurations on consumer email services

### **Red Flags This Tool Catches:**
- ✅ Exchange servers configured for personal iCloud accounts
- ✅ Microsoft 365 tenants on personal Apple domains
- ✅ Google Workspace indicators on personal Gmail accounts
- ✅ Enterprise verification records on consumer domains
- ✅ Suspicious MX record changes on personal email services

## 🚨 **When You Need This Tool**

**Use this tool if you experience:**
- Cannot enroll your device in MDM because "another organization already manages it"
- Unexpected device restrictions or policies appearing
- Apps installing automatically without your permission
- Corporate certificates or profiles you didn't install
- Device settings you cannot change
- Work/school accounts appearing that you didn't add

## 📦 **Installation**

```bash
# Clone the repository
git clone https://github.com/SunofvaLLM/MDMFraudCheck.git
cd MDMFraudCheck

# Install dependencies
pip install -r requirements.txt
```

**Requirements (requirements.txt):**
```txt
requests>=2.25.0
dnspython>=2.1.0  
python-whois>=0.7.3
```

## 🔍 **Usage**

### **Basic Scan**
```bash
python EnrollmentChecker.py your.personal.email@gmail.com
```

### **Save Evidence for Legal Action**
```bash
python EnrollmentChecker.py your.email@icloud.com --save-evidence evidence_report.json
```

### **Quick Threat Assessment**
```bash
python EnrollmentChecker.py your.email@yahoo.com --quiet
```

### **Export Full JSON Report**
```bash
python EnrollmentChecker.py your.email@outlook.com --json
```

## 🎯 **Supported Personal Email Providers**

This tool specifically monitors these **personal email services** for unauthorized enterprise management:

| Provider | Domains | Risk Factors |
|----------|---------|-------------|
| **Apple** | icloud.com, me.com, mac.com | Exchange autodiscover, MS tenants |
| **Google** | gmail.com, googlemail.com | Workspace enrollment, enterprise MX |
| **Microsoft** | outlook.com, hotmail.com, live.com, msn.com | Intune enrollment, org access |
| **Yahoo** | yahoo.com, ymail.com, rocketmail.com | Enterprise MX changes |
| **Others** | aol.com, protonmail.com, zoho.com, etc. | DNS tampering, verification records |

## 🚨 **Threat Levels Explained**

### 🚨 **CRITICAL** - Unauthorized enrollment detected
- **Strong evidence** of privacy violation
- **Immediate action required**
- **Legal consultation recommended**
- **Example:** Personal iCloud account showing Exchange server configuration

### ⚠️ **HIGH** - Suspicious patterns detected  
- **Likely unauthorized** enrollment
- **Investigation needed**
- **Device checks required**
- **Example:** Personal Gmail with Google Workspace indicators

### ⚠️ **MODERATE** - Concerning indicators
- **Potential security issues**
- **Monitoring recommended** 
- **Verify account settings**
- **Example:** Unexpected DNS security records

### ✅ **LOW** - Normal personal account
- **No significant threats** detected
- **Continue normal security practices**
- **Account appears properly personal**

## 📱 **What To Do If Threats Are Found**

### **CRITICAL/HIGH Threats - Immediate Actions:**

1. **🛑 STOP using the email on personal devices immediately**
2. **📱 Check ALL devices for MDM profiles:**
   - **iOS:** Settings → General → VPN & Device Management
   - **Android:** Settings → Security → Device Admin Apps
   - **macOS:** System Preferences → Profiles  
   - **Windows:** Settings → Accounts → Access work or school

3. **🔒 Secure your account:**
   - Change password immediately
   - Enable 2FA if not already active
   - Review account recovery methods
   - Check for unknown administrator access

4. **📋 Document everything:**
   - Screenshot all findings
   - Save the tool's evidence report
   - Export account activity logs
   - Record any device restrictions

5. **⚖️ Take legal action:**
   - File complaint with privacy authorities (FTC, ICO, etc.)
   - Contact email provider's abuse department  
   - Consult with privacy attorney
   - Consider law enforcement if criminal activity suspected

### **Legal Violations This May Indicate:**
- **Computer Fraud and Abuse Act (CFAA)** violations
- **Electronic Communications Privacy Act (ECPA)** violations
- **State privacy law** violations
- **International data protection** regulation violations

## 🛡️ **Prevention Tips**

- **Never** add personal email accounts to work/school devices
- **Be cautious** about QR codes or setup links from organizations
- **Regularly check** device management settings
- **Enable** security notifications on all accounts
- **Use separate** email addresses for work and personal use
- **Monitor** for unexpected device behavior

## 📊 **Example Output**

```bash
$ python EnrollmentChecker.py sunofva@icloud.com

🔍 Scanning sunofva@icloud.com for unauthorized MDM enrollment...
🎯 Target: Personal icloud.com account
🚨 Looking for: Enterprise management on consumer email

================================================================================
🕵️ UNAUTHORIZED MDM ENROLLMENT DETECTION REPORT
================================================================================
Email: sunofva@icloud.com
Domain: icloud.com (PERSONAL EMAIL PROVIDER)
Analysis Time: 2025-09-09T02:48:33.361533Z

🚨 THREAT LEVEL: CRITICAL
Assessment: STRONG evidence of unauthorized MDM enrollment detected
Alerts Found: 2 (2 critical, 0 high)

🚩 UNAUTHORIZED ENROLLMENT INDICATORS:
--------------------------------------------------

1. 🚨 CRITICAL ALERT
   Finding: Exchange Autodiscover detected on personal Apple domain
   Implication: This should NEVER exist for personal iCloud accounts
   🔧 Action Required: IMMEDIATE - Check all devices for unauthorized MDM profiles

2. 🚨 CRITICAL ALERT
   Finding: Microsoft 365 tenant detected for personal Apple domain
   Implication: Personal Apple domains should not have Microsoft tenants
   🔧 Action Required: IMMEDIATE - Apple ID may be compromised

🚨 EMERGENCY RESPONSE PLAN
--------------------------------------------------
⚡ IMMEDIATE ACTIONS:
  🚨 STOP using this email on personal devices immediately
  📱 Check ALL devices for MDM profiles in settings
  🔒 Change password and enable 2FA if not already done
  📋 Document everything - take screenshots of all findings
  ⚖️ Consider this a privacy violation requiring legal action
```

## 🔧 **Repository Structure**

```
MDMFraudCheck/
├── EnrollmentChecker.py      # Main detection script
├── requirements.txt          # Python dependencies
├── README.md                 # This file
├── examples/                 # Example outputs and test cases
│   ├── critical_case.json    # Example of CRITICAL threat
│   └── normal_case.json      # Example of LOW threat
└── docs/                     # Additional documentation
    ├── legal-resources.md    # Legal guidance and contacts
    └── device-checks.md      # Device-specific MDM check instructions
```

## ⚖️ **Legal Disclaimer**

**This tool is for legitimate security research and personal protection only.**

### **Important Notes:**
- Only analyzes **publicly available information**
- Cannot access private systems or data
- Results indicate **potential** violations requiring investigation
- Users are responsible for verifying findings
- Consult legal counsel for specific guidance
- Report criminal activity to appropriate authorities

### **When This Tool Is Appropriate:**
- ✅ Checking your own personal email accounts
- ✅ Investigating suspected privacy violations
- ✅ Gathering evidence for legal proceedings  
- ✅ Educational security research
- ✅ Helping others with consent

### **When This Tool Is NOT Appropriate:**
- ❌ Checking someone else's email without permission
- ❌ Corporate espionage or competitive intelligence
- ❌ Violation of terms of service
- ❌ Any illegal or unethical purposes

## 🆘 **Emergency Contacts**

### **Privacy Authorities:**
- **US:** Federal Trade Commission (FTC) - consumer.ftc.gov
- **EU:** Local Data Protection Authority
- **UK:** Information Commissioner's Office (ICO) - ico.org.uk
- **Canada:** Privacy Commissioner - priv.gc.ca

### **Email Provider Abuse Contacts:**
- **Apple:** reportphishing@apple.com
- **Google:** abuse@google.com  
- **Microsoft:** abuse@microsoft.com
- **Yahoo:** abuse@yahoo.com

## 📞 **Support & Resources**

### **Privacy Organizations:**
- Electronic Frontier Foundation (EFF) - eff.org
- Privacy International - privacyinternational.org
- Center for Democracy & Technology - cdt.org

### **Legal Resources:**
- ACLU Privacy & Technology - aclu.org
- Local bar association privacy attorneys
- Pro bono legal clinics

## 🤝 **Contributing**

Found a new unauthorized enrollment pattern? Want to improve detection accuracy?

1. Fork the repository
2. Create a feature branch (`git checkout -b new-detection-method`)
3. Commit your changes (`git commit -am 'Add new MDM fraud detection'`)
4. Push to the branch (`git push origin new-detection-method`)
5. Create a Pull Request

**When reporting issues:**
- Provide sanitized examples (remove personal information)
- Describe the specific threat scenario
- Include expected vs actual behavior

## 🔄 **Updates & Maintenance**

This tool is actively maintained to detect new unauthorized enrollment methods. 

**Stay updated:**
- Watch this repository for updates
- Check releases for new detection capabilities
- Follow [@SunofvaLLM](https://github.com/SunofvaLLM) for security research updates

## 📈 **Version History**

- **v1.0.0** - Initial release with Apple ID, Gmail, and Microsoft detection
- **v1.1.0** - Added DNS tampering detection and legal documentation features
- **v1.2.0** - Enhanced threat assessment and emergency response planning

## 🏆 **Recognition**

This tool was developed in response to real-world cases of unauthorized MDM enrollment affecting personal device privacy. Special thanks to the privacy community for reporting patterns and helping improve detection accuracy.

---

## 🚨 **Remember: Privacy is a fundamental right. Unauthorized device management is a serious violation that deserves immediate action and legal consequences.**

**If you discover unauthorized enrollment, you are not alone. Document everything, seek legal help, and fight back against privacy violations.**

### **Report Issues & Get Help:**
- **Repository Issues:** https://github.com/SunofvaLLM/MDMFraudCheck/issues
- **Security Vulnerabilities:** Contact [@SunofvaLLM](https://github.com/SunofvaLLM) privately
- **Privacy Violations:** Document with this tool and contact legal authorities

**Star ⭐ this repository if it helped protect your privacy!**
