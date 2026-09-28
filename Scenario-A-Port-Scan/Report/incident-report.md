\# Incident Report #001 — TCP Port Scan Investigation



\## 1. Executive Summary



A network traffic investigation was conducted using Wireshark against the

provided Nmap standard scan PCAP.



The analysis identified repeated TCP SYN packets originating from

192.168.100.103 and targeting 192.168.100.102 across a large number of

TCP destination ports.



The destination ports appeared in a non-sequential order. No SYN/ACK,

RST, or other return traffic from the target was observed in the supplied

PCAP.



The observed traffic pattern is consistent with TCP SYN-based network

service reconnaissance.



\---



\## 2. Detection



The activity was identified through packet-level analysis in Wireshark.



The following display filter was used:



tcp.flags.syn == 1 \&\& tcp.flags.ack == 0



This revealed repeated SYN probes from:



Source:

192.168.100.103



Destination:

192.168.100.102



\---



\## 3. Evidence



\### Protocol Analysis



The PCAP contained approximately 2,004 packets:



\- 2,000 TCP packets

\- 4 ARP packets



Approximately 99.8% of packets were TCP.



\### Endpoint Analysis



The primary hosts observed were:



| Host | Traffic |

|---|---|

| 192.168.100.103 | Source |

| 192.168.100.102 | Target |



The capture showed approximately 2,000 TCP packets travelling from

192.168.100.103 toward 192.168.100.102.



\### Port Scanning Evidence



Multiple TCP destination ports were targeted, including examples such as:



\- 21

\- 22

\- 23

\- 25

\- 53

\- 80

\- 443

\- 9999



The destination ports appeared in a non-sequential order.



\---



\## 4. Response Analysis



The following filters were tested:



tcp.flags.syn == 1 \&\& tcp.flags.ack == 1



Result:



No packets observed.



The following filter was also tested:



tcp.flags.reset == 1



Result:



No packets observed.



Therefore, no SYN/ACK or TCP RST response was observed from the target

in the supplied PCAP.



\---



\## 5. IOC Extraction



| Type | Value | Description |

|---|---|---|

| Source IP | 192.168.100.103 | Host generating SYN probes |

| Target IP | 192.168.100.102 | Host receiving probes |

| Protocol | TCP | Protocol used for scanning |

| Example Port | 21 | Targeted TCP port |

| Example Port | 22 | Targeted TCP port |

| Example Port | 53 | Targeted TCP port |

| Example Port | 80 | Targeted TCP port |

| Example Port | 9999 | Targeted TCP port |



Both IP addresses are private/internal addresses.



\---



\## 6. MITRE ATT\&CK



Technique:



T1046 — Network Service Scanning



The observed behaviour is consistent with network service enumeration

through TCP port scanning.



\---



\## 7. Investigation Findings



The source host 192.168.100.103 generated repeated TCP SYN probes

against 192.168.100.102.



The probes targeted a large number of TCP destination ports and appeared

in a non-sequential order.



No response traffic from the target was observed in the supplied PCAP.



The available evidence therefore supports the identification of network

reconnaissance activity.



\---



\## 8. Verdict



The observed traffic is consistent with a TCP SYN port scan targeting

192.168.100.102 from 192.168.100.103.



The PCAP does not by itself establish why the scan occurred or whether

the source system was compromised.



\---



\## 9. Recommended Response



1\. Identify the owner and role of 192.168.100.103.

2\. Determine whether the scan was authorised security testing.

3\. If unauthorised, investigate the source host for additional suspicious

&#x20;  activity.

4\. Review authentication, process creation, and endpoint security logs

&#x20;  from the source host.

5\. Review other internal hosts for similar scanning behaviour.

6\. Consider network controls or segmentation if the activity is confirmed

&#x20;  to be unauthorised.

