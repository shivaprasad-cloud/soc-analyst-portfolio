# CoCanDa Phishing Email Analysis

## Overview

This project documents my investigation of a phishing email received by a Gmail account. The goal was to determine whether the email was legitimate or malicious by analyzing the email headers, decoding the email body, examining the attachment, extracting indicators of compromise (IOCs), and mapping the attack to the MITRE ATT&CK framework.

This project demonstrates the basic workflow a SOC analyst follows when investigating a suspicious email.

---

## Objectives

* Analyze the email headers.
* Verify the sender information.
* Check email authentication results (SPF).
* Decode the Base64-encoded email body.
* Inspect the attached PDF file.
* Extract Indicators of Compromise (IOCs).
* Check the sender IP address and file hash using VirusTotal.
* Map the attack to the MITRE ATT&CK framework.
* Decide whether the email is malicious.

---

## Tools Used

* Gmail
* CyberChef
* Linux `base64` command
* VirusTotal

---

## Investigation Process

### 1. Collected the Email Headers

I first collected the complete email headers from Gmail to identify the sender, routing information, and authentication results.

### 2. Decoded the Email Body

The email body was encoded in Base64. I decoded it using CyberChef and verified the output using the Linux `base64` command to read the original message.

### 3. Examined the Attachment

I inspected the attached PDF by checking its file signature (magic bytes) to confirm that the file type matched its extension.

### 4. Verified with VirusTotal

I searched the sender IP address and the attachment hash in VirusTotal to check whether they had been reported as malicious.

### 5. Extracted Indicators of Compromise

I collected important indicators such as the sender email address, Reply-To address, sender IP, domain, subject, and attachment name.

### 6. Mapped the Attack

Finally, I mapped the phishing email to the MITRE ATT&CK framework to identify the technique used by the attacker.

---

## Skills Demonstrated

* Email Header Analysis
* Phishing Investigation
* Base64 Decoding
* File Signature Verification
* IOC Extraction
* VirusTotal Analysis
* MITRE ATT&CK Mapping
* Incident Documentation

---

## Conclusion

After analyzing the email headers, decoding the message, inspecting the attachment, and checking the available threat intelligence, I concluded that the email was a phishing attempt. This project helped me understand how to investigate suspicious emails, collect evidence, and document the findings in a structured SOC analyst report.
