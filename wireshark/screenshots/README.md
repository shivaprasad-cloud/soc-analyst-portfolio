# Investigation Screenshots

This folder contains the screenshots collected during my network traffic investigation. Each screenshot supports the findings documented in the investigation report and shows the evidence used during the analysis.

---

## 1. TCP SYN Scan Detection

**File:** `01-tcp-syn-scan.png`

This screenshot shows multiple TCP SYN packets captured in Wireshark using the following display filter:

```text
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

The traffic contains a large number of SYN packets sent to different destination ports without corresponding ACK responses. This behavior is commonly associated with TCP SYN port scanning.

---

## 2. DNS VERSION.BIND Query

**File:** `02-dns-version-bind-query.png`

This screenshot shows a DNS `VERSION.BIND` query observed during the investigation.

The query is commonly used to identify the DNS server software version. Attackers often perform this type of reconnaissance to gather information about the target before attempting further attacks.

**Wireshark Display Filter**

```text
dns
```

---

## 3. HTTP Login Page Probe

**File:** `03-http-login-probe.png`

This screenshot shows repeated HTTP GET requests to the `/login.rsp` endpoint.

The repeated requests indicate web application reconnaissance, where an attacker attempts to discover valid login pages or accessible resources on the web server.

**Wireshark Display Filter**

```text
http.request.uri contains "/login.rsp"
```

---

## Summary

These screenshots provide the supporting evidence used during the investigation. They demonstrate how Wireshark was used to identify network reconnaissance activities, including TCP SYN scanning, DNS fingerprinting, and web application probing.
