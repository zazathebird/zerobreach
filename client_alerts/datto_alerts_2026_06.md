# Datto RMM Malware Alerts — June 2026

## Summary
3 distinct malware threats detected across 3 systems. All quarantined by Microsoft Defender or Datto AV.

---

## Alert 1: Trojan HTML/Phish Detector
**Date:** 2026-06-11  
**Severity:** HIGH  
**Threat Name:** `Trojan:HTML/Phish.PJ!MSR`  
**Threat Category:** Trojan  
**Threat Type:** Known Bad  
**Detection Source:** Microsoft Defender (Scan)  
**Status:** Quarantined  

**Affected System:**
- OS: Windows 11 Professional 24H2 64-bit
- File Path:** `C:\Users\[User-A]\AppData\Local\Temp\Diagnostics\OUTLOOK\Additional\Additional1781121704716740500_F9407205-CFE5-479B-AA0E-755980743DE8.log`
- Process Name:** `Additional1781121704716740500_F9407205-CFE5-479B-AA0E-755980743DE8.log`

**Analysis:**
- Phishing HTML file detected in Outlook diagnostic temp folder
- Likely downloaded via email or email attachment extraction
- Temporary Outlook diagnostics path suggests email client involvement
- Multiple detections on same system over time (quarantine + abandon pattern)

**Detection ID:** `{5F3802C9-82B3-4B28-8D7A-EBCECF631D28}`

---

## Alert 2: PUA / Potentially Unwanted Program
**Date:** 2026-06-19  
**Severity:** HIGH  
**Threat Name:** `PUA/W32.PUP`  
**Threat Category:** Malware  
**Threat Type:** Generic PUA  
**Detection Source:** Datto AV (Real-time)  
**Status:** Quarantined + Remediated  

**Affected System:**
- OS: Windows 11 Professional 24H2 64-bit
- File Path:** `C:\Users\[User-B]\Downloads\setuppdf_869850.exe`
- File SHA256:** `859389cdb7c9c3764f9e068dcf79629b8c8322ab1f36a585bdbf1d35ba31bbe7`
- Process Name:** `SetupPDF_869850.exe`

**Analysis:**
- Masqueraded as legitimate PDF reader installer ("SetupPDF_*" naming pattern)
- Found in Downloads folder — user-initiated download or email attachment
- Generic PUP signature suggests behavior-based or reputation detection
- Successfully quarantined and removed

**Detection ID:** `ef0243d2a98344cfd3cfbd5c16c65da2a47355bb`  
**Engine Version:** Datto AV 8.4.2.10

---

## Alert 3: Trojan JS/Redirector
**Date:** 2026-05-11  
**Severity:** HIGH  
**Threat Name:** `Trojan:JS/Redirector.ACT!MTB`  
**Threat Category:** Trojan  
**Threat Type:** Known Bad  
**Detection Source:** Microsoft Defender (Scan)  
**Status:** Quarantined  

**Affected System:**
- OS: Windows 11 Professional 24H2 64-bit
- File Path:** `C:\Users\[User-C]\AppData\Local\Microsoft\Olk\Attachments\[extraction-path]\Invoice_Payment_Details_137522-ERR-579-1GFTLU4Z34U.H8ORW.htm->(SCRIPT0000)`
- Process Name:** `Invoice_Payment_Details_137522-ERR-579-1GFTLU4Z34U.H8ORW.htm->(SCRIPT0000)`

**Analysis:**
- JavaScript trojan embedded in HTML file
- Found in Outlook Attachment cache folder (`Microsoft\Olk\Attachments\`)
- Filename mimics legitimate business invoice (social engineering)
- Variant detection pattern (ACT!MTB) suggests Trojan.Generic.ACT detection
- `(SCRIPT0000)` notation indicates script object extraction by email client

**Detection ID:** `{ED753C2D-8CCF-43F2-B384-C347ACA9B8D4}`

---

## Recommended Additions to ZeroBreach

### 1. New Threat Signatures (detection_signatures.json)

**Add to `trojan_file_patterns`:**
```json
"*.log" when path contains "Temp\\Diagnostics\\OUTLOOK"
"*SetupPDF*.exe"
"*Invoice*.htm"
"*Payment*.htm"
```

**Add to `yara_lite_rules`:**
```json
{
  "Name": "HTML/Phish.PJ - Phishing HTML Trojan",
  "Pattern": "(?i)(SetupPDF|Invoice.*Payment.*Details).*\\.(exe|htm|html|log)",
  "Severity": "HIGH"
},
{
  "Name": "JS/Redirector.ACT - Trojan JavaScript Redirector",
  "Pattern": "(?i)(\\(SCRIPT\\d{4}\\)|Redirector).*\\.htm(?:l)?",
  "Severity": "HIGH"
}
```

### 2. New Email Attachment Scanning Phase

Currently missing: dedicated Outlook/email attachment scanning. Recommend adding:
- Scan `$env:LOCALAPPDATA\Microsoft\Outlook\*.pst` for suspicious attachments
- Scan `$env:LOCALAPPDATA\Microsoft\Olk\Attachments\` for quarantine artifacts
- Pattern match invoice/payment documents + embedded scripts

### 3. SHA256 IOC List

Add to custom IOC file or built-in list:
```json
"859389cdb7c9c3764f9e068dcf79629b8c8322ab1f36a585bdbf1d35ba31bbe7"
```

---

## Common Attack Pattern
All three alerts follow a **phishing + social engineering** vector:
1. Fake invoice or PDF installer sent via email
2. Recipient downloads or opens attachment
3. Trojan/PUP/redirector executes
4. Defender catches it at execution time

**Mitigation Focus:**
- Email gateway filtering (not ZeroBreach scope)
- User awareness training (not ZeroBreach scope)
- **ZeroBreach scope:** Improve detection of email attachment artifacts and obfuscated scripts
