# SSH Brute Force Incident Report

## Title

SSH Brute Force Attack Detected Against Local Test Environment

## Date

**Date:** 03 July 2026

**Time:** Approximately 10:10 IST

## Severity

**Medium**

**Reason:** Multiple failed SSH authentication attempts were detected against a single user account. No successful login occurred and no evidence of system compromise was found.

---

## Timeline

**10:10:11 IST**

* Initial SSH session disconnected from source IP **127.0.0.1**.

**10:10:12 IST**

* Multiple authentication failures recorded by the PAM authentication module.

**10:10:14 IST**

* Seven failed SSH password authentication attempts detected against the **testuser** account.

**10:10:15 IST**

* All SSH sessions were terminated after unsuccessful authentication attempts.

---

## What Happened

A series of SSH authentication attempts targeted the local account **testuser**. The attack originated from **127.0.0.1** using the SSH service on port 22. Multiple incorrect passwords were attempted within a few seconds, indicating brute-force behavior. Every authentication attempt failed, and no unauthorized access was obtained.

---

## Affected System

**Hostname:** shiva-VirtualBox

**Operating System:** Ubuntu Linux

**Service:** OpenSSH Server (sshd)

**Target Account:** testuser

---

## Indicators of Compromise (IOCs)

**Source IP Address**

* 127.0.0.1

**Target Username**

* testuser

**Service**

* SSH

**Destination Port**

* 22

**Authentication Method**

* Password Authentication

**Observed Events**

* Multiple PAM authentication failures
* Multiple "Failed password" log entries
* SSH connection closures after failed authentication

---

## MITRE ATT&CK Mapping

**Technique ID:** T1110

**Technique Name:** Brute Force

**Tactic:** Credential Access

---

## Analysis

The authentication logs show repeated password authentication failures against a single user account within a short time period. This behavior is consistent with a brute-force password attack. No successful authentication events were observed, indicating that the attack was unsuccessful.

---

## Decision

* Incident classified as **Medium Severity**.
* No successful compromise detected.
* Activity identified as a brute-force attack simulation in a controlled lab environment.
* Continue monitoring SSH authentication logs for repeated attempts.

---

## Recommended Actions

1. Block repeated authentication attempts using Fail2Ban or similar intrusion prevention software.
2. Disable SSH password authentication where possible and use SSH key authentication.
3. Disable direct root login over SSH.
4. Enforce strong password policies.
5. Enable Multi-Factor Authentication (MFA) where supported.
6. Continuously monitor SSH logs for abnormal authentication activity.
7. Configure alerting for excessive failed login attempts.

---

## Evidence Collected

**Log Source**

* systemd journal (`journalctl -u ssh`)

**Relevant Log Events**

* Multiple `pam_unix(sshd:auth): authentication failure`
* Multiple `Failed password for testuser from 127.0.0.1`
* Multiple `Connection closed by authenticating user`

---

## Conclusion

The investigation confirmed an SSH brute-force attack targeting the **testuser** account. The attack generated multiple failed authentication attempts but did not result in a successful login or system compromise. The incident demonstrates how SSH authentication logs can be used to identify brute-force activity and map it to the MITRE ATT&CK framework.
