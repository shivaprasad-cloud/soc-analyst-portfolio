# Phishing Email Incident Report

## Incident Information

| Field              | Value               |
| ------------------ | ------------------- |
| Incident ID        | PHISH-2026-001      |
| Investigation Date | 09 July 2026        |
| Analyst            | Shivaprasad Karoshi |
| Severity           | High                |
| Category           | Phishing Email      |
| Status             | Confirmed Phishing  |

---

# Executive Summary

A suspicious email was investigated after it was received by a Gmail user. The investigation focused on analyzing the email headers, decoding the email body, examining the attachment, extracting Indicators of Compromise (IOCs), and verifying available threat intelligence.

The email showed several phishing indicators, including failed SPF authentication, a mismatched Reply-To address, a suspicious sender domain, and an attachment whose file signature did not match its extension. Based on the collected evidence, the email was classified as a confirmed phishing attempt.

---

# Incident Details

| Field        | Value                                                         |
| ------------ | ------------------------------------------------------------- |
| Recipient    | [themajoronearth@gmail.com](mailto:themajoronearth@gmail.com) |
| Subject      | A Hope to CoCanDa                                             |
| Sender       | [billjobs@microapple.com](mailto:billjobs@microapple.com)     |
| Reply-To     | [negeja3921@pashter.com](mailto:negeja3921@pashter.com)       |
| Return-Path  | [billjobs@microapple.com](mailto:billjobs@microapple.com)     |
| Sending IP   | 93.99.104.210                                                 |
| Sending Host | emkei.cz                                                      |
| Attachment   | PuzzleToCoCanDa.pdf                                           |

---

# Investigation Methodology

The investigation followed these steps:

1. Collected the complete email headers from Gmail.
2. Reviewed the sender information and authentication results.
3. Decoded the Base64-encoded email body using CyberChef and verified it using the Linux `base64` command.
4. Examined the attachment by checking its magic bytes.
5. Verified the sending host using VirusTotal.
6. Extracted Indicators of Compromise (IOCs).
7. Mapped the attack to the MITRE ATT&CK framework.
8. Determined the final verdict based on the collected evidence.

---

# Email Header Analysis

The email headers contained several indicators that suggested the message was not sent from a legitimate source.

### Findings

* The sender claimed to be **[billjobs@microapple.com](mailto:billjobs@microapple.com)**.
* The **Reply-To** address was **[negeja3921@pashter.com](mailto:negeja3921@pashter.com)**, which did not match the sender's email address.
* The email originated from **93.99.104.210** using the host **emkei.cz**.
* The SPF authentication check failed.

### Authentication Result

| Check | Result       |
| ----- | ------------ |
| SPF   | Failed       |
| DKIM  | Not Observed |
| DMARC | Not Observed |

A failed SPF check indicates that the sending server was not authorized to send emails on behalf of the claimed domain. The mismatched Reply-To address is another common phishing indicator because it redirects replies to an attacker-controlled mailbox.

---

# Email Body Analysis

The email body was encoded in Base64. After decoding, the message claimed that the "CoCanDians" had been abducted and requested one billion CoCanDs in cash along with a spaceship. The sender instructed the recipient to solve a puzzle contained in the attached file.

Although the message appears humorous, it encourages the recipient to interact with the attachment. Attackers often use unusual stories or curiosity to persuade users to open malicious files.

Key observations:

* Uses an unusual fictional scenario.
* Encourages the recipient to open the attachment.
* Attempts to create curiosity.
* Contains the message **"Don't Trust Your Eyes"**, directing attention to the attachment.

---

# Attachment Analysis

The email contained an attachment named **PuzzleToCoCanDa.pdf**.

The attachment was examined using CyberChef to verify its file signature.

### Findings

| Property         | Result              |
| ---------------- | ------------------- |
| File Name        | PuzzleToCoCanDa.pdf |
| File Extension   | .pdf                |
| Magic Bytes      | 50 4B 03 04         |
| Actual File Type | ZIP Archive         |

The magic bytes **50 4B 03 04** identify the file as a ZIP archive rather than a PDF document. This mismatch between the file extension and the actual file type is suspicious because attackers sometimes disguise files to encourage users to open them.

---

# VirusTotal Analysis

The sending host **emkei.cz** was searched in VirusTotal.

### Result

* **5 out of 91** security vendors flagged the host as malicious.

Although VirusTotal detections alone are not enough to classify an email as malicious, this result supports the other findings from the investigation, including the failed SPF authentication and mismatched Reply-To address.

---

# Indicators of Compromise (IOCs)

| IOC Type         | Value                                                         |
| ---------------- | ------------------------------------------------------------- |
| Subject          | A Hope to CoCanDa                                             |
| Sender Email     | [billjobs@microapple.com](mailto:billjobs@microapple.com)     |
| Reply-To Address | [negeja3921@pashter.com](mailto:negeja3921@pashter.com)       |
| Recipient        | [themajoronearth@gmail.com](mailto:themajoronearth@gmail.com) |
| Sending IP       | 93.99.104.210                                                 |
| Sending Host     | emkei.cz                                                      |
| Sender Domain    | microapple.com                                                |
| Attachment       | PuzzleToCoCanDa.pdf                                           |

---

# MITRE ATT&CK Mapping

| Tactic         | Technique                | ID        |
| -------------- | ------------------------ | --------- |
| Initial Access | Phishing                 | T1566     |
| Initial Access | Spearphishing Attachment | T1566.001 |

The attacker attempted to gain initial access by sending a phishing email containing an attachment intended to persuade the recipient to interact with it.

---

# Risk Assessment

| Category     | Level |
| ------------ | ----- |
| Likelihood   | High  |
| Impact       | High  |
| Overall Risk | High  |

If the attachment had been opened without verification, it could have resulted in malware execution or further compromise of the recipient's system.

---

# Recommendations

* Do not open unexpected email attachments.
* Verify sender information before responding.
* Report suspicious emails to the security team.
* Block known malicious senders and domains where appropriate.
* Continue monitoring for similar phishing attempts.
* Provide phishing awareness training to users.

---

# Final Verdict

**Classification: Confirmed Phishing**

The investigation identified multiple phishing indicators:

* SPF authentication failed.
* The Reply-To address differed from the sender's address.
* The email originated from the host **emkei.cz**.
* VirusTotal reported **5/91** detections for the sending host.
* The attachment's file extension did not match its actual file type.
* The email used social engineering techniques to encourage interaction with the attachment.

Based on these findings, the email is classified as a **Confirmed Phishing** attempt.

---

# Skills Demonstrated

* Email Header Analysis
* SPF Authentication Analysis
* Base64 Decoding
* CyberChef File Analysis
* Magic Byte Verification
* VirusTotal Threat Intelligence
* IOC Extraction
* MITRE ATT&CK Mapping
* Phishing Investigation
* Incident Reporting
