
# Phishing-Email-Analysis-Soc-Documentation-Report

## 🔹 Overview

This project documents a real-world phishing email I received in Gmail that impersonates a **hiring manager** and asks the recipient to complete an external **“background report.”** The goal is to preserve evidence, extract indicators-of-compromise (IOCs), analyze the email’s delivery and social-engineering techniques, and produce a clear, reproducible forensic workflow that can be shown in a GitHub portfolio.
<img width="1855" height="873" alt="Screenshot 2025-09-15 210615" src="https://github.com/user-attachments/assets/bd690f4e-3787-4e84-bb01-f78d93f199cc" />

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







----
1. Mismatch in domain: Email from `@consultant.com` but claims Kforce Inc.
2. Social engineering: Premature “Congratulations!” before interview process.
3. Unusual background check request via third-party link.
4. Redirect URL (`afflat3d3.com`) — common in credential/PII harvesting.
5. Request for sensitive information (background check results + resume + phone).
6. Authentication (SPF/DKIM/DMARC) passes for consultant.com, not Kforce.
7. Originating IP: `103.76.241.19` — not tied to Kforce.
8. Routing through `mout.mail.com` servers — not corporate infrastructure.
9. Generic, vague signature — “Claire Divas, Hiring Manager.”


