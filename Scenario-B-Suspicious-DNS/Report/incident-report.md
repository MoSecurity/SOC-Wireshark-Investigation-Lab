\# Incident Report #002 — Suspicious DNS / Remote Shell Investigation



\## 1. Executive Summary



A network traffic capture was investigated using Wireshark to identify suspicious DNS-related activity.



Initial analysis showed normal DNS traffic between internal hosts. However, further investigation identified a separate TCP session communicating over destination port 53.



The TCP session was established between:



\- Source: `192.168.1.3:1396`

\- Destination: `192.168.1.2:53`



The traffic was not normal DNS communication. After reconstructing the TCP stream, the payload revealed a Windows command shell running over the TCP/53 connection.



The reconstructed stream contained:



```text

Microsoft Windows XP \[Version 5.1.2600]



C:\\> dir



followed by a directory listing from the remote Windows system.



This provides direct evidence that TCP port 53 was being used as a remote command-shell communication channel.



The activity is therefore assessed as:



Confirmed suspicious non-DNS remote-shell activity over TCP port 53.



The capture also contains legitimate DNS queries, including a query for www.www.com resolving to 63.215.91.200. This DNS traffic was analysed separately from the suspicious TCP/53 session.



2\. Investigation Objective



The objectives of this investigation were:



Identify unusual DNS-related network activity.

Determine whether TCP/UDP port 53 traffic represented legitimate DNS communication.

Identify suspicious internal hosts.

Reconstruct suspicious network sessions.

Extract potential Indicators of Compromise (IOCs).

Determine whether the traffic represented remote command execution.

Map the observed behaviour to MITRE ATT\&CK.

Produce a final security assessment.

3\. Tools Used

Primary Tool

Wireshark

Analysis Techniques

Protocol Hierarchy

IPv4 Endpoints

IPv4 Conversations

Display Filters

TCP stream analysis

Follow TCP Stream

DNS packet inspection

TCP conversation analysis

IOC extraction

4\. PCAP Overview



The capture contained multiple network protocols.



The Protocol Hierarchy showed approximately:



131 total packets

124 IPv4 packets

6 UDP packets

6 DNS packets

118 TCP packets

TLS traffic

Telnet traffic

HTTP traffic

ARP and other lower-level traffic



The presence of DNS traffic alone did not indicate malicious behaviour.



Further investigation was therefore required to determine whether any traffic was using DNS-related ports for purposes other than DNS.



5\. Endpoint Analysis



IPv4 endpoint analysis identified the following hosts:



IP Address	Packets	Role / Observation

83.170.75.178	10	External endpoint

140.112.253.189	1	External endpoint

192.168.1.1	6	Internal host

192.168.1.2	118	Internal host / TCP port 53

192.168.1.3	110	Internal host / suspicious client

205.227.136.203	3	External endpoint



The most significant communication was between:



192.168.1.3

&#x20;       |

&#x20;       | TCP/53

&#x20;       |

192.168.1.2

6\. Initial DNS Analysis



The display filter:



dns



was used to identify DNS traffic.



The capture contained several legitimate-looking DNS requests and responses.



Examples included:



192.168.1.3 → 192.168.1.1

PTR query



and a DNS query involving:



www.com



A DNS response also contained:



www.www.com



with an A record:



63.215.91.200



The presence of this DNS response was not considered sufficient evidence of malicious activity by itself.



The investigation therefore continued by examining traffic using TCP port 53.



7\. Suspicious TCP/53 Traffic



The following Wireshark display filter was applied:



tcp.port == 53



This revealed a TCP session between:



192.168.1.3:1396

&#x20;       ↕

192.168.1.2:53



The traffic contained:



TCP handshake

Bidirectional data transfer

PSH/ACK packets

TCP acknowledgements

Retransmissions

Session termination



The important observation was that the traffic was carried over TCP port 53 rather than UDP DNS traffic.



8\. TCP Conversation Analysis



The TCP conversation contained:



Field	Value

Address A	192.168.1.3

Port A	1396

Address B	192.168.1.2

Port B	53

Total Packets	24

A → B	14 packets

B → A	10 packets

Total Data	Approximately 4 KB

Duration	Approximately 5.312 seconds

Stream ID	1



The session was clearly bidirectional.



This indicated that the connection was being used to exchange application data rather than simply performing a TCP connection attempt.



9\. TCP Stream Reconstruction



The TCP session was reconstructed using:



Right Click

→ Follow

→ TCP Stream



The reconstructed stream contained:



Microsoft Windows XP \[Version 5.1.2600]



C:\\> dir



dir



Volume in drive C has no label.

Volume Serial Number is FF47-80EB



Directory of C:\\



The stream then returned a directory listing from the Windows system.



This is the strongest evidence in the investigation.



The traffic therefore contained an interactive Windows command shell operating through the TCP/53 connection.



10\. Evidence of Command Execution



The command:



C:\\> dir



was observed directly inside the reconstructed TCP stream.



The remote system returned the directory contents of the Windows C:\\ drive.



This demonstrates:



A command shell was available.

Commands could be sent through the network connection.

Commands were executed on the remote Windows system.

Output was returned through the same TCP session.



This is substantially different from normal DNS request/response behaviour.



11\. Important DNS vs TCP/53 Distinction



The investigation identified two different types of traffic:



Normal DNS



DNS traffic was observed using DNS queries and responses.



Example:



www.www.com

→

63.215.91.200

Suspicious TCP/53 Traffic



A separate connection was observed:



192.168.1.3:1396

&#x20;       ↕

192.168.1.2:53



The TCP payload contained a Windows command shell.



Therefore, the primary finding is not simply:



"A suspicious DNS query occurred."



Instead, the stronger finding is:



"A remote command shell was carried over TCP port 53, which is not normal DNS application behaviour."



This distinction is important for SOC analysis.



12\. IOC Extraction

Network Indicators

Type	Value	Description

Internal Source IP	192.168.1.3	Source of suspicious TCP/53 session

Internal Destination IP	192.168.1.2	Destination listening/communicating on TCP/53

Source Port	1396	Client-side TCP port

Destination Port	53	TCP port used for remote shell

Protocol	TCP	Transport protocol

DNS Resolved IP	63.215.91.200	Address returned for www.www.com

Host Indicator



Observed operating system:



Microsoft Windows XP

Command Indicator



Observed command:



dir

13\. Threat Intelligence Analysis



The DNS response contained:



www.www.com

→

63.215.91.200



The public IP address was checked against available public IP information.



The address belongs to infrastructure associated with Level 3 / Lumen network space.



The public IP alone was not treated as proof of compromise or malicious infrastructure.



The stronger evidence came from the packet contents themselves:



TCP/53

\+

Bidirectional application data

\+

Windows command shell

\+

Command execution

\+

Returned command output



Therefore, the security assessment is based primarily on observed network behaviour rather than the reputation of the resolved IP address.



14\. MITRE ATT\&CK Mapping

T1059.003 — Windows Command Shell



The strongest MITRE ATT\&CK mapping is:



T1059.003 — Windows Command Shell



Reason:



The reconstructed network stream directly showed a Windows command prompt and command execution:



C:\\> dir



This demonstrates the use of the Windows command shell.



15\. Investigation Findings



The investigation established the following:



Finding 1



Normal DNS traffic was present in the capture.



Finding 2



A separate TCP session used destination port 53.



Finding 3



The TCP session was bidirectional.



Finding 4



The session carried application-level data rather than DNS messages.



Finding 5



TCP stream reconstruction revealed a Windows command shell.



Finding 6



The command:



dir



was executed.



Finding 7



The resulting directory listing was transmitted back through the same network session.



Finding 8



The behaviour is consistent with remote shell activity using TCP port 53 as the communication channel.



16\. Security Assessment

Verdict



Confirmed suspicious non-DNS remote-shell activity over TCP/53.



The PCAP contains legitimate DNS traffic, but the investigated TCP/53 session represents a different communication channel.



The reconstructed stream demonstrates that:



192.168.1.3

&#x20;       ↓

TCP/53

&#x20;       ↓

192.168.1.2

&#x20;       ↓

Windows Command Shell

&#x20;       ↓

dir

&#x20;       ↓

Directory Listing



This behaviour is inconsistent with normal DNS functionality.



The evidence supports the conclusion that TCP port 53 was being used to transport remote command-shell communication.



17\. Recommended SOC Response



If this traffic were observed in a real enterprise environment, recommended actions would include:



Immediate Actions

Identify the systems associated with:

192.168.1.3

192.168.1.2

Determine which system initiated the TCP/53 connection.

Check whether TCP/53 is legitimately required in the environment.

Isolate the affected host if unauthorised remote-shell activity is confirmed.

Review endpoint security logs for additional command execution.

Search for additional connections involving the same hosts.

Review firewall and proxy logs for unusual TCP/53 traffic.

18\. Additional Investigation



A SOC analyst should also investigate:



Windows Security Event Logs

Sysmon process creation events

Command-line logging

Network connection events

Persistence mechanisms

User accounts involved

Other connections from 192.168.1.3

Other services listening on port 53

Similar TCP/53 connections elsewhere in the environment



Useful Windows/Sysmon evidence would include:



4688 — Process Creation



and relevant Sysmon network/process events.



19\. Key Lessons



This investigation demonstrates an important SOC principle:



Port numbers do not guarantee application protocol.



Port 53 is normally associated with DNS, but an analyst should not automatically assume that every packet using port 53 is DNS traffic.



The correct workflow is:



Identify unusual port

&#x20;       ↓

Inspect protocol

&#x20;       ↓

Check packet direction

&#x20;       ↓

Follow the TCP stream

&#x20;       ↓

Reconstruct application data

&#x20;       ↓

Extract evidence

&#x20;       ↓

Determine behaviour

&#x20;       ↓

Assess threat



In this case, following the TCP stream changed the investigation from a potentially normal DNS event into clear evidence of remote command-shell activity.



20\. Screenshots / Evidence



The following screenshots were collected during the investigation:



01\_protocol\_hierarchy.png

02\_ipv4\_endpoints.png

03\_ipv4\_conversations.png

04\_dns\_packets.png

05\_tcp\_port\_53.png

06\_follow\_tcp\_stream.png

07\_tcp\_conversation.png

08\_dns\_response\_www\_com.png



The most important evidence is:



05\_tcp\_port\_53.png

06\_follow\_tcp\_stream.png

07\_tcp\_conversation.png

21\. Final Conclusion



The investigation identified suspicious network activity involving TCP port 53.



Although the capture contained legitimate DNS traffic, a separate TCP session between 192.168.1.3:1396 and 192.168.1.2:53 carried a Windows command shell.



The reconstructed stream showed command execution and returned command output, providing direct evidence of remote shell activity.



The observed behaviour should therefore be treated as a security incident requiring further endpoint and network investigation.



Final Verdict



Confirmed suspicious non-DNS remote-shell activity over TCP/53.

