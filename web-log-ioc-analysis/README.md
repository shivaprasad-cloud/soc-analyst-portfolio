# Web Server Log Analysis: Scanning, SQL Injection, and Directory Traversal

*Analysis of a public Apache access log dataset (ocatak/apache-http-logs) containing traffic from the Acunetix web vulnerability scanner against a DVWA test instance.*

## Overview

I went through the `acunetix.txt` log from this dataset and pulled out three distinct attack patterns: an automated scan, a SQL injection attempt, and a directory traversal attempt. All three came from the same source IP (192.168.4.25), which lines up with this being scanner tool output rather than a mix of independent attackers. Below is what I found and why each one stood out.

## Environment

- **Log source:** [acunetix.txt](https://github.com/ocatak/apache-http-logs/blob/master/acunetix.txt) (ocatak/apache-http-logs)
- **Target application:** DVWA (Damn Vulnerable Web App), hosted at 192.168.4.161
- **Attacker IP:** 192.168.4.25
- **Log format:** Apache combined log format

## Finding 1: SQL Injection

```
192.168.4.25 - - [22/Dec/2016:16:20:01 +0300] "GET /index.php/2-uncategorised/1--1'%20OR%202%2b196-196-1=0%2b0%2b0%2b1%20or%20'01Fg5alL'=' HTTP/1.1" 200 3304 "http://192.168.4.161/DVWA" "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21"
```

URL-decoded, the payload reads:

```
1'--1' OR 2+196-196-1=0+0+0+1 or '01Fg5alL'='
```

This isn't a simple `OR 1=1`. The attacker (or in this case, the scanner) breaks out of the query with a single quote, then uses arithmetic (`2+196-196-1`) that evaluates to a true condition, instead of writing the boolean check directly. That's likely an attempt to slip past simple pattern-matching filters that only look for literal strings like `OR 1=1`. A second `OR` clause with an unmatched quote is tacked on right after, probably testing a slightly different injection variant in the same request.

What makes this one worth flagging over other SQLi attempts in the same log: it returned **200 OK with a 3304-byte response**, not a 400 or 500 error. That means the malformed query was actually processed by the backend rather than rejected outright — worth investigating further in a real incident, since a successful response to injected SQL syntax is a stronger signal than a blocked one.

**MITRE ATT&CK:** T1190 — Exploit Public-Facing Application

## Finding 2: Directory Traversal

```
192.168.4.25 - - [22/Dec/2016:16:18:13 +0300] "GET /sdk/../../../../../../../../../../../../../etc/passwd HTTP/1.1" 400 485 "-" "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21"
```

Thirteen `../` sequences chained together, trying to climb out of the web root and reach `/etc/passwd` — the standard proof-of-concept target for traversal on a Linux host. Unlike the SQLi attempt above, this one got a **400 Bad Request**, meaning either the web server or an input filter caught the malformed path before it reached anything sensitive.

The same IP repeated this exact technique multiple times over the next couple minutes, swapping the entry point (`/sdk/`, `/index.php/`, the site root) and occasionally switching the target file from `/etc/passwd` to `/proc/version`. That repetition is what ties this finding to the scanning pattern below — it's the same underlying technique, just fired at different injection points.

**MITRE ATT&CK:** T1083 — File and Directory Discovery

## Finding 3: Scanning Pattern

```
192.168.4.25 - - [22/Dec/2016:16:18:13 +0300] "GET /sdk/../../../../../../../../../../../../../etc/passwd HTTP/1.1" 400 485
192.168.4.25 - - [22/Dec/2016:16:18:13 +0300] "GET /sdk/../../../../../../../../../../../../../etc/passwd HTTP/1.1" 400 485
192.168.4.25 - - [22/Dec/2016:16:19:26 +0300] "GET //.././.././.././.././.././.././.././../etc/./passwd%2500/2-uncategorised/1-testsayfasi HTTP/1.1" 400 485
192.168.4.25 - - [22/Dec/2016:16:19:26 +0300] "GET /../../../../../../../../../../etc/passwd/2-uncategorised/1-testsayfasi HTTP/1.1" 400 485
192.168.4.25 - - [22/Dec/2016:16:19:27 +0300] "GET /index.php/../../../../../../../../../../../../../../../proc/version-uncategorised/1-testsayfasi HTTP/1.1" 400 485
192.168.4.25 - - [22/Dec/2016:16:19:43 +0300] "GET /index.php/2-uncategorised/1-../../../../../../../../../../../../../../../proc/version HTTP/1.1" 400 485
```

A few things jump out when these lines are read together instead of one at a time:

- **Same source IP** across every request, in a window of under two minutes
- **Identical response signature** — every single request returns `400 485`, meaning the server (or a filter in front of it) handled each attempt the same way. A real user's traffic naturally varies in response size; this doesn't, because it's the same rejected request pattern over and over
- **Systematic variation** — the requests aren't identical, they're a tool working through a list: different entry paths (`/sdk/`, `/index.php/`, site root), different traversal string formats (some using `%2500` null-byte encoding, some using double-encoded slashes), cycling between two target files
- **Timing** — several requests land in the same second, which isn't something a person typing by hand produces

This is the behavioral fingerprint of an automated scanner working through a payload list, not a person manually probing the site. Notably, the User-Agent string across all of this traffic reads as a normal Chrome browser — this scanner isn't identifying itself the way a Nikto or sqlmap default configuration would, so a detection rule looking only at User-Agent strings would miss it entirely. The rate and pattern of requests is the more reliable signal here.

**MITRE ATT&CK:** T1595 — Active Scanning

## IOC Summary

| Indicator | Value |
|---|---|
| Source IP | 192.168.4.25 |
| Target | 192.168.4.161/DVWA |
| User-Agent | Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21 |
| SQLi endpoint | /index.php/2-uncategorised/1 |
| Traversal targets | /etc/passwd, /proc/version |
| Response pattern (traversal/scan) | 400, 485 bytes |
| Response pattern (SQLi) | 200, 3304 bytes |

## Notes

All traffic analyzed here is from a publicly available research dataset generated against a deliberately vulnerable test application (DVWA) — no live systems were involved.

## Tools Used

Manual log review (text search), Apache combined log format reference
