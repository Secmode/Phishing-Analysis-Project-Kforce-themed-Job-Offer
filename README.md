
# Phishing Investigation: Malicious Job Offer & MITRE Mapping

## 🔹 Overview

This project documents a real-world phishing email I received in Gmail that impersonates a **hiring manager** and asks the recipient to complete an external **“background report.”** The goal is to preserve evidence, extract indicators-of-compromise (IOCs), analyze the email’s delivery and social-engineering techniques, and produce a clear, reproducible forensic workflow that can be shown in a GitHub portfolio.
<img width="1855" height="873" alt="Screenshot 2025-09-15 210615" src="https://github.com/user-attachments/assets/bd690f4e-3787-4e84-bb01-f78d93f199cc" />
<img width="1890" height="686" alt="image" src="https://github.com/user-attachments/assets/9c653d71-3835-4374-98a7-23a84a32ed25" />


## Observation

I received a **“Congratulations — You Have Been Selected”** job-offer email that immediately asked me to complete a **background check.** While the spelling and grammar appeared correct, the message used premature praise (“Congratulations”) and requested an external background check — a known **social-engineering tactic** designed to prompt quick compliance.  

The included link pointed to a tracked redirect URL, consistent with **credential/PII harvesting scams**. I did not interact with the link on my production machine. Instead, I saved the full raw message, opened it in **Sublime Text** for review, and performed all further analysis in an **isolated lab VM** to safely investigate the redirect and extract IOCs.

## Raw Email Analysis (Sublime Text)
<img width="1491" height="838" alt="image" src="https://github.com/user-attachments/assets/878a9b0a-456b-4b6a-a672-abe867bbc173" />



## Breakdown of the suspicious elements found in the raw email:
### Mismatch in Identity
Email is sent from `@consultant.com` but claims to be from **Kforce Inc.**  
- **Domain reputation checks:**  
  - VirusTotal flagged the domain as suspicious (3/95 security vendors).   **AND**  urlscan.io showed the IP address resolving to `185.158.133.1` (Frankfurt am Main, Germany), which does **not** match the U.S.-based infrastructure typically used by Kforce.
<img width="1904" height="620" alt="image" src="https://github.com/user-attachments/assets/8efc23d1-f832-4c6e-84cb-81d0fcd9ad51" />
<img width="1570" height="600" alt="image" src="https://github.com/user-attachments/assets/e0f1a316-d33a-40fe-bd13-7e283d9ced7b" />

### Social Engineering — Premature Praise And Suspicious Background Check Request
- **Subject line:** **“Congratulations!** You Have Been Selected for Kforce Inc”.
   This creates urgency and excitement before any real interview process — a classic social engineering hook **MITRE ATT&CK Mapping ID: T1598** – Phishing (general)
<img width="1885" height="281" alt="image" src="https://github.com/user-attachments/assets/c49df92c-6d4c-42e2-8ca3-ed3ebdd7c3be" />


### Phishing Link with Redirect
**Classic URL obfuscation and redirection.**
- Google SafeRedirect → Actual pointing to a suspicious Malicious destination website flagged by multiple security platforms.
<img width="1783" height="305" alt="image" src="https://github.com/user-attachments/assets/7f52c948-c956-4e5d-8966-f2260e8242a0" />
<img width="1844" height="723" alt="image" src="https://github.com/user-attachments/assets/353bc736-4d14-4f2e-a8ad-90ad60045f64" />
<img width="1023" height="342" alt="image" src="https://github.com/user-attachments/assets/0be3c96b-8778-4923-9ed7-eba98d470451" />
<img width="1861" height="393" alt="image" src="https://github.com/user-attachments/assets/89dd6a4a-be5d-4eea-833c-13f6b07e71c0" />


### Header Analysis — Pass but Suspicious
- **SPF, DKIM, and DMARC pass**, but only for consultant.com.
This means the email is technically authenticated, but for the wrong domain — confirming **domain misuse / business impersonation.**
<img width="1395" height="789" alt="image" src="https://github.com/user-attachments/assets/8634b29a-57ac-42bc-826b-222d289e8f3a" />

### Originating IP Address
 - **Mismatch between mail.com webmail (client) location Bangladesh Jhenida and claimed company location.**
- Received: from mout.mail.com (mout.mail.com. [74.208.4.201]) by mx.google.com ... **Role: This is the sending mail server’s IP — the server that tried to deliver the email to Gmail.**
- Received: from [103.76.241.19] ([103.76.241.19]) by web-mail.mail.com ... **Role: This is the originating client IP — the device that actually composed or submitted the email.**
<img width="1857" height="553" alt="Screenshot 2025-09-16 044944" src="https://github.com/user-attachments/assets/33127115-65cd-46a9-a49a-fe7ef6cdfb55" />
<img width="1444" height="319" alt="image" src="https://github.com/user-attachments/assets/066c7e9b-027d-463b-8f0f-17095bbd83ac" />
<img width="1697" height="941" alt="image" src="https://github.com/user-attachments/assets/5377662c-456f-4bb2-bf70-78c33ec77d0b" />
<img width="1406" height="537" alt="image" src="https://github.com/user-attachments/assets/bc46a220-03bf-4ba1-bae5-4469a84338b8" />

## Phishing Email Analysis: Unusual Routing

### Observations

- Sent through `mout.mail.com` → **not corporate infrastructure**.  
- Origin IP `103.76.241.19` has **no reverse DNS** → suspicious source.  
- Email came from **mail.com**, not Kforce’s official MX → unusual routing.  
- SPF/DKIM **pass only validates sending permission**, not legitimacy of content.  
- Combined with the **malicious link** (`afflat3d3.com`) → strong phishing indicators.
<img width="793" height="582" alt="image" src="https://github.com/user-attachments/assets/16cf2671-939d-4a92-a2e4-2c2182a6e243" />


> **Note:** This analysis is for **educational purposes only**. No conclusions are drawn about the security practices of the impersonated company.











----
# Phishing Email Analysis Report – Kforce Inc Impersonation

<details>
<summary>Headers</summary>

Date: Mon, 15 Sep 2025 16:32:01 +0200
Subject: Re: Congratulations! You Have Been Selected for Kforce Inc

To: Damilola Ajewole damilolaajewolesun@gmail.com
From: Claire Divas Claire.Divas@consultant.com

Reply-To: Claire.Divas@consultant.com
Return-Path: Claire.Divas@consultant.com

Sender IP: 103.76.241.19
Resolve Host: No reverse DNS found (suspicious)

Message-ID: trinity-02aa31d3-e4d2-4e15-8bc4-9d54e4dab056-1757946721461@3c-app-mailcom-lxa05

In-Reply-To: CAL6Dpq8bbVx=LKxGCdzzN4HBxgzQqdMS4wW8N7j6UqU23UkANg@mail.gmail.com

Received Path:

Email sent from 103.76.241.19 → web-mail.mail.com → Google MX → Recipient inbox.

External mail server (mail.com) used instead of Kforce corporate MX.

Authentication Results:

SPF: Pass (authorized sender)

DKIM: Pass

DMARC: Pass (policy: QUARANTINE)


</details>

<details>
<summary>URLs</summary>

- **Malicious URL:** [afflat3d3.com](https://afflat3d3.com/trk/lnk/894935A3-834A-4FD6-BB13-EF5DA75BC6EC/?o=28908&c=918277&a=716387&k=DFA1C0722440B87420F8A55EC1EEFC9C&l=32442&s1=priya)  
  - Flagged by VirusTotal and urlscan.io
  - Likely credential harvesting or malware delivery
  - Unusual routing through external mail.com


</details>

<details>
<summary>Attachments</summary>

- Attachment Name: None  
- MD5: N/A  
- SHA1: N/A  
- SHA256: N/A  

</details>

<details>
<summary>Description</summary>

The email impersonates Kforce Inc and attempts to trick the recipient with a fake “job selection” message.  

**Key findings:**
- Sender impersonation: @consultant.com (not Kforce)
- Social engineering: Premature praise, urgent request
- Malicious link: afflat3d3.com
- Data exfiltration: Requests resume, contact info, and screenshots
- Unusual routing through mail.com


</details>

<details>
<summary>Artifact Analysis</summary>

**Sender Analysis:**  
- Name: Claire Divas  
- Email: Claire.Divas@consultant.com  
- IP: 103.76.241.19, mail.com network  
- MITRE ATT&CK: T1585.001 – Establish Accounts: Email Accounts  


**URL Analysis:**  
- Malicious URL: afflat3d3.com/trk/lnk/...  
- MITRE ATT&CK: T1566 – Phishing, T1204.002 – User Execution: Malicious Link  


**Attachment Analysis:**  
- No attachments; attempts data exfiltration via URL

</details>

<details>
<summary>Social Engineering Techniques</summary>

- Premature praise to entice the user  
- Urgent request for action  
- Authority figure: “Hiring Manager”  
- Data gathering: resume, screenshot, contact info  
- MITRE ATT&CK: T1566 – Phishing, T1204 – User Execution


</details>

<details>
<summary>Verdict</summary>

- Type: Phishing  
- Risk Level: High  
- Recommendation: Do not click links, do not reply, delete email


</details>

<details>
<summary>Defense Actions</summary>

- Block sender domain (@consultant.com) and IP 103.76.241.19  
- Quarantine/remove email from inboxes  
- Educate users on phishing and social engineering indicators  
- Monitor network for attempts to access afflat3d3.com  
- Report domain/email to threat intelligence (VirusTotal, abuse mail)  
- Update email security rules to detect similar patterns


</details>
<details>
<summary>Tools Used</summary>

**Text Editor / Analysis:**  
- [Sublime Text](https://www.sublimetext.com/) – for raw email and header inspection  

**Operating System / Environment:**  
- [Ubuntu](https://ubuntu.com/) virtual machine / lab environment  

**MITRE ATT&CK Reference:**  
- [T1598 – Phishing](https://attack.mitre.org/techniques/T1598/)  

**Sandbox / URL Analysis:**  
- [Joe Sandbox](https://www.joesandbox.com/analysis/1492476/0/html?utm_source=chatgpt.com)  
- [PhishTool](https://app.phishtool.com/analysis/68c87bde5d029972a0b0876b)  
- [Scamadviser – afflat3b3.com](https://www.scamadviser.com/check-website/afflat3b3.com?utm_source=chatgpt.com#google_vignette)  
- [Gridinsoft Online Virus Scanner – afflat3b3.com](https://gridinsoft.com/online-virus-scanner/url/afflat3b3-com?utm_source=chatgpt.com)  
- [Scam Detector – afflat3e3.com](https://www.scam-detector.com/validator/afflat3e3-com-review/?utm_source=chatgpt.com)  

**WHOIS / IP Intelligence:**  
- [DomainTools WHOIS – 74.208.4.201](https://whois.domaintools.com/74.208.4.201)  
- [AbuseIPDB – 74.208.4.201](https://www.abuseipdb.com/check/74.208.4.201)  
- [IPInfo – 103.76.241.19](https://ipinfo.io/103.76.241.19#block-abuse)  

**OSINT / People Search:**  
- [LinkedIn Search – Claire Divas](https://www.linkedin.com/search/results/all/?keywords=Claire%20Divas&origin=GLOBAL_SEARCH_HEADER&sid=ssv)  

**URL Scanning / Threat Intelligence:**  
- [URLScan.io Result](https://urlscan.io/result/01995550-c451-710f-a78c-fee54f5b37cd/)  
- [VirusTotal URL Scan](https://www.virustotal.com/gui/url/1e168f5a31a82e8335af723d9fabdc64929eae984c021fa5b8069e31605092d9?nocache=1)  

**Other References / Tools:**  
- [Microsoft Azure MHA Lab](https://mha.azurewebsites.net/)  
- [GCHQ GitHub Resources](https://gchq.github.io/C)  
- [MXToolBox – Email Header Analyzer](https://mxtoolbox.com/Public/Tools/EmailHeaders.aspx?huid=a89beb1d-4545-440e-ae75-03a9f90ceec2)  

</details>
<img width="766" height="674" alt="image" src="https://github.com/user-attachments/assets/0296f8f9-4e43-4c60-82c8-89e2348bfb64" />



