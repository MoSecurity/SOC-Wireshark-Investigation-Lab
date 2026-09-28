# Incident Report #003 — Possible C2 / HTTP Beaconing Investigation

## 1. Executive Summary

A network traffic capture was investigated using Wireshark to identify possible command-and-control (C2) communication.

The investigation identified internal host `172.16.8.49` generating repeated outbound HTTP connections to multiple external IP addresses over TCP port 80.

The traffic showed several characteristics associated with automated C2-like communication:

- Repeated independent TCP connections.
- Repeated HTTP POST requests.
- Short and unusual URI paths.
- `application/x-www-form-urlencoded` payloads.
- Large encoded-looking request bodies.
- Connections to multiple external destinations.
- Highly regular connection timing in observed bursts.
- Similar connection durations and packet counts across multiple sessions.

A particularly clear pattern was observed between:

`172.16.8.49 → 146.59.71.167:80`

Multiple independent connections were established at approximately 2.7-second intervals during observed bursts.

A reconstructed HTTP stream also showed:

```text
POST /irpw/ HTTP/1.1
Host: www.grinswakebthu.info
Content-Type: application/x-www-form-urlencoded
Content-Length: 3225
```

The request body contained a large encoded-looking data block. The server returned:

```text
HTTP/1.1 404 Not Found
```

The 404 response does not by itself make the activity benign; the assessment is based on the overall communication pattern.

### Final Assessment

**Strongly indicative of automated C2-like HTTP beaconing activity.**

The PCAP provides strong network-behaviour evidence consistent with automated command-and-control communication, but the capture alone does not establish the identity of a specific malware family, operator, or definitive ownership of the external infrastructure.

---

## 2. Investigation Objective

The objectives of the investigation were:

1. Identify the internal host generating unusual outbound traffic.
2. Identify repeated external communications.
3. Determine the application protocol used.
4. Inspect HTTP request structure and payload characteristics.
5. Determine whether connections were independent or merely continuation packets.
6. Analyse connection timing and repetition.
7. Extract potential Indicators of Compromise (IOCs).
8. Map the observed behaviour to MITRE ATT&CK.
9. Produce a defensible security assessment.

---

## 3. Tools Used

### Primary Tool

- Wireshark

### Analysis Techniques

- Protocol and endpoint analysis
- IPv4 Conversations
- TCP Conversations
- Display filters
- HTTP request filtering
- Follow TCP Stream
- TCP stream analysis
- Connection-start analysis
- Timing analysis
- IOC extraction

---

## 4. PCAP Overview

The analysed capture was:

```text
2026-08-09-traffic-analysis-exercise.pcap
```

The initial Wireshark view showed a mixture of network activity including DHCP, IGMP, ARP, HTTP and other protocols.

IPv4 endpoint analysis identified several internal and external systems. The internal host that became the primary focus was:

```text
172.16.8.49
```

This host generated a large amount of network traffic and communicated with numerous external IP addresses.

---

## 5. Endpoint Analysis

The IPv4 endpoint analysis identified several high-volume hosts.

Important internal systems included:

| IP Address | Approx. Packets | Observation |
|---|---:|---|
| `172.16.8.49` | 13,744 | Primary investigation host |
| `172.16.8.53` | 8,547 | High-volume internal host |
| `172.16.8.8` | 3,794 | Internal host |

The investigation focused on `172.16.8.49` because its TCP conversations showed numerous outbound connections to external IP addresses over TCP/80.

---

## 6. Conversation Analysis

IPv4 conversation analysis showed that `172.16.8.49` communicated with many external destinations.

Examples included:

```text
172.16.8.49 → 146.59.71.167
172.16.8.49 → 81.2.196.19
172.16.8.49 → 38.182.168.246
172.16.8.49 → 45.130.41.161
172.16.8.49 → 66.29.149.91
172.16.8.49 → 89.110.89.25
172.16.8.49 → 104.21.42.23
172.16.8.49 → 104.21.76.210
172.16.8.49 → 121.54.163.148
172.16.8.49 → 156.247.51.39
172.16.8.49 → 172.67.162.153
172.16.8.49 → 172.67.219.130
172.16.8.49 → 172.64.155.76
```

Many of these connections used TCP destination port 80.

This observation alone is not evidence of C2 because legitimate applications can communicate with many web servers. Further HTTP and timing analysis was therefore performed.

---

## 7. Filtering HTTP Traffic

The following Wireshark filter was used:

```text
http.request && ip.src == 172.16.8.49
```

The results showed repeated HTTP requests originating from `172.16.8.49`.

Examples included:

```text
POST /11lj/
POST /tza3/
POST /irpw/
POST /lqjm/
POST /ttsm/
POST /nxc3/
POST /v2r8/
POST /ujvq/
```

The requests commonly used:

```text
Content-Type: application/x-www-form-urlencoded
```

and contained large payloads that were not human-readable in the packet view.

---

## 8. HTTP Stream Analysis — `81.2.196.19`

One reconstructed TCP stream between:

```text
172.16.8.49 → 81.2.196.19:80
```

contained:

```http
POST /11lj? HTTP/1.1
Host: www.moxom.online
Content-Type: application/x-www-form-urlencoded
Content-Length: 69101
Connection: close
```

The request contained a large encoded-looking payload.

The server returned:

```text
HTTP/1.1 404 Not Found
```

The 404 response indicates that the requested resource was not found, but it does not explain the unusual client-side behaviour.

The important evidence was the combination of:

- HTTP POST
- External destination
- Short URI
- Large form-urlencoded payload
- Encoded-looking content
- Repeated similar traffic from the same internal host

---

## 9. HTTP Stream Analysis — `146.59.71.167`

A second reconstructed TCP stream was analysed:

```text
172.16.8.49 → 146.59.71.167:80
```

The request contained:

```http
POST /irpw/ HTTP/1.1
Host: www.grinswakebthu.info
Content-Type: application/x-www-form-urlencoded
Content-Length: 3225
Connection: close
```

The body contained a large encoded-looking data block.

The server returned:

```text
HTTP/1.1 404 Not Found
```

Again, the response code was not treated as the main indicator.

The significant observation was that the same internal host repeatedly generated similarly structured HTTP POST traffic to external infrastructure.

---

## 10. Distinguishing HTTP Requests from Continuations

During the investigation, several packet rows were labelled:

```text
POST ... Continuation
```

These were not counted as separate HTTP requests.

They represented additional TCP segments belonging to a larger HTTP request.

This distinction was important because counting every continuation as a separate beacon would produce an incorrect conclusion.

The investigation therefore used TCP SYN packets and TCP stream IDs to identify independent connections.

---

## 11. Independent Connection Analysis

The following filter was used to isolate new TCP connections:

```text
ip.src == 172.16.8.49 &&
tcp.dstport == 80 &&
tcp.flags.syn == 1 &&
tcp.flags.ack == 0
```

The analysis identified numerous independent connections from `172.16.8.49` to external TCP/80 destinations.

For example, connections to:

```text
146.59.71.167:80
```

used separate TCP stream IDs including:

```text
242
243
244
245
246
247
248
249
414
415
416
417
418
419
420
421
```

This demonstrated that the observed activity was not simply one long TCP connection.

---

## 12. Beaconing / Timing Analysis

The strongest timing pattern was observed for:

```text
172.16.8.49 → 146.59.71.167:80
```

Observed connection start times included approximately:

```text
394.57 s
397.24 s
399.92 s
402.60 s
405.30 s
407.96 s
410.66 s
413.36 s
```

The intervals between successive connections were approximately:

```text
2.67 s
2.68 s
2.69 s
2.67 s
2.70 s
2.70 s
```

A later burst was also observed around:

```text
772.26 s
774.94 s
777.64 s
780.32 s
783.00 s
785.70 s
788.38 s
791.07 s
```

Again, the interval was approximately 2.7 seconds within the burst.

This regularity is consistent with automated communication rather than an individual manually browsing a website.

It is important to note that regular timing alone does not prove malicious C2. The conclusion is based on the combination of timing, repeated HTTP POST behaviour, unusual URI paths, encoded-looking payloads, and multiple external destinations.

---

## 13. Connection Structure

The TCP Conversations analysis showed repeated sessions with similar characteristics.

Many connections contained approximately:

```text
100–104 packets
```

and durations around:

```text
1.6–1.8 seconds
```

Other sessions contained smaller numbers of packets and shorter durations, corresponding to connection establishment or termination activity.

The repeated structure across multiple destinations strengthened the assessment that the traffic was generated automatically.

---

## 14. Observed HTTP Indicators

### Internal Host

```text
172.16.8.49
```

### External IPs Observed

```text
146.59.71.167
81.2.196.19
38.182.168.246
45.130.41.161
66.29.149.91
89.110.89.25
104.21.42.23
104.21.76.210
121.54.163.148
156.247.51.39
172.64.155.76
172.67.162.153
172.67.219.130
```

### Observed Domains

```text
www.moxom.online
www.grinswakebthu.info
```

These domains were observed directly in HTTP Host headers in the supplied PCAP.

They should be treated as network indicators for investigation rather than automatically classified as malicious solely from their presence in the capture.

### Observed URI Examples

```text
/11lj/
/tza3/
/irpw/
/lqjm/
/ttsm/
/nxc3/
/v2r8/
/ujvq/
```

### Protocol

```text
HTTP over TCP/80
```

### HTTP Method

```text
POST
```

### Content Type

```text
application/x-www-form-urlencoded
```

---

## 15. MITRE ATT&CK Mapping

### T1071.001 — Application Layer Protocol: Web Protocols

The observed traffic maps to:

```text
T1071.001 — Web Protocols
```

MITRE ATT&CK describes this technique as the use of web application protocols such as HTTP/HTTPS for command-and-control communication and notes that adversaries can embed command or response data within web traffic. MITRE's current Enterprise ATT&CK page also includes HTTP POST-based C2 examples. 

Reference:

https://attack.mitre.org/techniques/T1071/001/

The mapping is based on the observed HTTP communication pattern. It does not identify a specific malware family or threat actor.

---

## 16. Investigation Findings

### Finding 1 — High outbound activity

`172.16.8.49` generated substantial network traffic and communicated with many external destinations.

### Finding 2 — Repeated HTTP POST traffic

The host repeatedly generated HTTP POST requests to external systems.

### Finding 3 — Unusual URI structure

Several POST requests used short paths such as:

```text
/irpw/
/11lj/
/tza3/
/lqjm/
/ttsm/
```

### Finding 4 — Encoded-looking payloads

The request bodies contained large non-human-readable data blocks.

### Finding 5 — Multiple external destinations

Similar traffic structures were observed to multiple external IP addresses.

### Finding 6 — Independent TCP connections

TCP SYN analysis confirmed that the traffic consisted of multiple independent TCP sessions rather than a single long-lived connection.

### Finding 7 — Regular timing

Connections to `146.59.71.167` showed approximately 2.7-second intervals within observed bursts.

### Finding 8 — Repeated session structure

Multiple connections showed similar packet counts and durations.

### Finding 9 — Automated behaviour

The combination of repeated sessions, regular timing, similar HTTP structure, and multiple destinations is consistent with automated network communication.

---

## 17. Security Assessment

### Verdict

**Strongly indicative of automated C2-like HTTP beaconing activity.**

The evidence supports the assessment that `172.16.8.49` was generating automated HTTP communication with external infrastructure.

The strongest indicators are:

```text
Internal host
172.16.8.49
        ↓
Repeated TCP/80 connections
        ↓
HTTP POST requests
        ↓
Short unusual URI paths
        ↓
Encoded-looking form data
        ↓
Multiple external destinations
        ↓
Regular connection timing
        ↓
C2-like beaconing pattern
```

The PCAP alone does not establish:

- The exact malware family.
- The identity of the threat actor.
- Whether every external IP belonged to the same operator.
- The exact commands exchanged.
- The exact process responsible on the endpoint.

Those questions require endpoint telemetry and additional network evidence.

---

## 18. Recommended SOC Response

If this activity were detected in a real enterprise environment, the following actions would be appropriate.

### Immediate Investigation

1. Identify the asset associated with `172.16.8.49`.
2. Identify the logged-in user at the relevant time.
3. Determine which process generated the HTTP connections.
4. Collect endpoint telemetry before making destructive changes.
5. Review EDR telemetry for suspicious processes and network connections.
6. Review DNS, proxy, firewall, and web gateway logs.
7. Search the environment for the observed domains and IP addresses.
8. Search for similar HTTP POST patterns from other hosts.

### Endpoint Investigation

Review:

```text
Windows Security Events
Sysmon Event ID 1 — Process Creation
Sysmon Event ID 3 — Network Connection
Browser/application history where appropriate
Scheduled Tasks
Services
Startup locations
Recent executable files
PowerShell activity
Command-line telemetry
```

### Containment

If endpoint evidence confirms compromise:

- Isolate the affected endpoint through EDR.
- Preserve relevant forensic evidence.
- Block confirmed malicious infrastructure according to organisational procedures.
- Reset credentials if credential compromise is identified.
- Hunt for lateral movement.
- Determine initial access and persistence mechanisms.

### Network Detection

A detection rule could look for:

```text
Repeated outbound HTTP POST
+
Rare/unusual destination
+
Short URI
+
Encoded or high-entropy payload
+
Regular connection intervals
```

This type of behavioural detection is preferable to relying only on static IP reputation.

---

## 19. Detection Opportunities

The observed behaviour suggests several useful SOC detections:

### Detection 1 — Repetitive HTTP POST Beaconing

Alert when a single internal host repeatedly sends HTTP POST requests to the same external destination at regular intervals.

### Detection 2 — Rare External HTTP Destinations

Alert when an endpoint makes repeated HTTP connections to previously unseen or low-prevalence external destinations.

### Detection 3 — Encoded HTTP Payloads

Investigate HTTP POST bodies that contain unusually large encoded or high-entropy content.

### Detection 4 — Browser-Like Headers from Non-Browser Processes

Correlate HTTP traffic with endpoint process telemetry to identify applications that imitate normal browser headers.

### Detection 5 — Multiple Destinations With Similar HTTP Behaviour

Look for a single endpoint contacting many external IPs using similar URI lengths, methods, headers, and timing.

MITRE ATT&CK's current detection guidance for T1071.001 includes detecting repetitive or beacon-like HTTP communication, POST-heavy behaviour, unusual domains/IPs, and network telemetry correlated with endpoint process data.

---

## 20. Limitations

This investigation was based on a network PCAP only.

The PCAP does not provide sufficient evidence to determine:

- The exact process responsible for the traffic.
- The malware family.
- The initial infection vector.
- Persistence mechanisms.
- The identity of the attacker.
- Whether every external endpoint was malicious.
- The exact contents or meaning of the encoded payload.

Therefore, the final assessment is deliberately based on observed network behaviour.

---

## 21. Lessons Learned

This investigation demonstrated several important SOC analysis principles.

### 1. Do not judge a connection by port number alone

TCP/80 does not automatically mean benign web browsing.

### 2. Do not count TCP continuation packets as separate requests

A single HTTP request can span many TCP segments.

### 3. Timing can reveal automation

Regular connection intervals can provide evidence of beacon-like behaviour.

### 4. Behaviour is more useful than reputation alone

A public IP address does not need to have a known malicious reputation for its traffic to deserve investigation.

### 5. Correlation strengthens detection

The strongest conclusion came from combining:

```text
HTTP method
+
URI structure
+
Payload characteristics
+
Destination diversity
+
Connection frequency
+
Timing
+
Session structure
```

rather than relying on one indicator.

---

## 22. Evidence Screenshots

Recommended screenshots for the GitHub repository:

```text
01_initial_traffic.png
02_ipv4_endpoints.png
03_ipv4_conversations.png
04_host_172.16.8.49_tcp.png
05_tcp_stream_81_2_196_19.png
06_http_post_activity.png
07_http_requests.png
08_http_hosts.png
09_moxom_host_activity.png
10_moxom_post_activity.png
12_tcp_stream_146_59_71_167.png
13_tcp_stream_243_timeline.png
14_connection_start_times.png
15_repeated_http_connections_01.png
15_repeated_http_connections_02.png
15_repeated_http_connections_03.png
```

The most important evidence is:

```text
02_ipv4_endpoints.png
03_ipv4_conversations.png
05_tcp_stream_81_2_196_19.png
06_http_post_activity.png
12_tcp_stream_146_59_71_167.png
14_connection_start_times.png
15_repeated_http_connections_01.png
15_repeated_http_connections_02.png
15_repeated_http_connections_03.png
```

---

## 23. Investigation Workflow

The completed investigation followed this workflow:

```text
PCAP
  ↓
Endpoint Analysis
  ↓
Conversation Analysis
  ↓
Identify 172.16.8.49
  ↓
Filter HTTP Traffic
  ↓
Identify Repeated POST Requests
  ↓
Follow TCP Streams
  ↓
Inspect HTTP Headers and Payloads
  ↓
Separate Requests from Continuations
  ↓
Identify Independent TCP Connections
  ↓
Analyse Connection Timing
  ↓
Extract IOCs
  ↓
MITRE ATT&CK Mapping
  ↓
C2-like Behaviour Assessment
```

---

## 24. Final Conclusion

The investigation identified a significant pattern of automated HTTP communication generated by internal host `172.16.8.49`.

The host established numerous independent TCP connections to external destinations over port 80. Multiple sessions contained HTTP POST requests with short URI paths and large encoded-looking form data.

The strongest evidence was the repeated and highly regular connection pattern observed between `172.16.8.49` and `146.59.71.167`, where independent connections occurred at approximately 2.7-second intervals within observed bursts.

Similar HTTP communication structures were also observed with multiple other external destinations.

Taken together, these characteristics are strongly indicative of automated C2-like HTTP beaconing behaviour.

Further endpoint investigation would be required to identify the responsible process, determine whether the host was compromised, identify any malware family, and establish the complete attack chain.

---

## 25. References

1. MITRE ATT&CK — T1071.001 Application Layer Protocol: Web Protocols  
   https://attack.mitre.org/techniques/T1071/001/

2. MITRE ATT&CK — T1071 Application Layer Protocol  
   https://attack.mitre.org/techniques/T1071/

3. MITRE ATT&CK — Detection of Web Protocol-Based C2 Over HTTP, HTTPS, or WebSockets  
   https://attack.mitre.org/detectionstrategies/DET0027/

4. Malware Traffic Analysis — 2026-08-09 Traffic Analysis Exercise  
   https://www.malware-traffic-analysis.net/2026/08/09/index.html
