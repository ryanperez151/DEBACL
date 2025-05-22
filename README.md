# DEBACL
### Dynamic Endpoint-Based Access Control List

![image](https://github.com/user-attachments/assets/3ed76d10-d0d5-4429-8a86-8392828f3d03)

Networks everywhere are under siege and remote-access VPN gateways are no different. Anything publicly exposed is vulnerable to probing and exploitation and VPNs are routinely targeted. These very VPN gateways we entrust to secure our network edges are also used as entry points by adversaries. In short, simply hanging a VPN on the Internet invites attack. Even adding stronger authentication still may leave doors open. Recommendations already exist on using strong authentication (queue MFA spiel), but sprayers gonna spray and exploit any flaws possible. To truly tighten security, we need a way to vet each connecting IP address associated with a device before it ever hits the VPN. Enter DEBACL. It acts like a bouncer with a guest list – only pre-approved, healthy devices are even allowed to knock on the VPN door.


#### Reasons to have a DEBACL --

•	Blocklists only catch the known bad. Threat feeds and geofilters are a great layer in our defenses and can block traffic from IPs or regions tied to past attacks but may not prevent new or unknown threats. By definition, they only cover addresses already identified as malicious. An attacker from a fresh and clean IP or a flavor of the month residential proxy may simply bypass these defenses.

•	Strong auth (MFA, certs) helps but isn’t foolproof. Robust authentication is crucial. In practice, however, adversaries still target any account lacking multi-factor protection. Password sprays and credential stuffing beatings will continue until morale improves. Even if 99.999% of accounts are safe, a single weakness is all a hacker needs. Even tech giants like Microsoft are susceptible to “password spray attacks that successfully compromised a legacy, non-production test tenant account that did not have multifactor authentication (MFA) enabled” (Microsoft Security Blog - January 2024).

•	Any Internet-facing VPN can be probed and exploited. Publicly exposed devices are scanned constantly. Recent years have been riddled with 0-day and n-day vulnerabilities plaguing VPNs. Likewise, breach reports show VPN portals being discovered and abused like an open door when configuration or patching lapses. In short, leaving a VPN ‘hole’ on your firewall invites attackers to knock, and sometimes let themselves in.

•	Zero Trust means shrinking exposure. Modern security mantras echo “never trust, always verify” – assume breaches and minimize trust zones. That means we should minimize the very existence of the open hole that a VPN represents. Limiting access to VPN servers reduces the attack surface. DEBACL embodies this Zero Trust principle by shrinking the exposed perimeter: only the smallest possible set of devices (those on the dynamic allow-list) can reach the VPN.


#### What Is DEBACL?

DEBACL (Dynamic Endpoint-Based Access Control List) is a way to ensure that only known, healthy endpoints can connect to a VPN (or similar ‘network edge’). 

In practice, this means the firewall or VPN gateway consults an automatically updated “allow list” of corporate devices (based on current public IPs) before letting anyone through. For example, an automated script might query your endpoint security platform (e.g. CrowdStrike Falcon) or device management system (e.g. Tanium) to retrieve all managed devices’ public IP addresses and potentially qualifying health status. These ‘known’ public IPs are then dynamically pushed into the firewall’s ACL. Modern NGFWs support this via features like Palo Alto’s External Dynamic Lists or Fortinet via Fabric Connectors/Automation Stitches. In other words, you point your firewall rule at the URL or data store containing your healthy-IP list, and the firewall automatically imports and enforces it. Only devices on that list – meaning managed, patched, and compliant laptops/mobile devices – are allowed to reach the VPN. Any other IP (unknown or unmanaged) is dropped at the edge. 

(As a comparison, some VPN posture solutions already check endpoint health before allowing connections – e.g. Cisco Meraki’s client claims to verify a device’s certificate, OS, antivirus, firewall status, and disk encryption before allowing VPN access - but DEBACL pushes that checking into the network layer itself.)


#### DEBACL Framework

1.	Managed endpoint connects to a public network. A managed device often connects to the network prior to local interactive and VPN client logon.

2.	Endpoint reports telemetry to EDR/RMM. Endpoint agents (like CrowdStrike Falcon or Tanium Client) reports in to management consoles. This typically includes the device’s current public IP, OS and patch level, security posture, etc.

3.	Compile a trusted-IP list. The EDR/RMM data ought to be continually aggregated and processed to determine which public IP addresses are related to managed/healthy devices. It effectively builds a list of IP addresses that correspond to “good” endpoints.

4.	Push DEBACL to the network gateway. An automation feeds the trusted-IP list to the edge firewall/VPN. The firewall’s ACL is reloaded or updated with this list.

5.	Enforce policy to “allow only DEBACL known IPs.” The firewall rule now permits traffic only from the DEBACL-sourced Ips to VPN server. Any incoming VPN connection from an IP not on the list is dropped or rejected before passing traffic to the VPN for authentication. The VPN portal becomes effectively invisible to unauthorized devices.

6.	Log and alert in SIEM. The list building, export, and updating operations along with connection attempts (allowed or dropped) should be forwarded to your SIEM or log server for auditing. This creates an audit trail showing which devices were permitted or blocked by the DEBACL. 


#### Benefits of DEBACL

•	Drastically reduced attack surface. By default, the VPN sees no one except those on the allow list. This turns the VPN’s “hole” in your firewall into a tiny pinprick. With DEBACL, random internet hosts can’t even reach the VPN for probing or exploitation.

•	Leverages existing endpoint investments. DEBACL taps the security data you already have. If you’re using CrowdStrike, Tanium, or any EDR/RMM, you already know which devices are healthy. DEBACL just uses that info to govern the network edge – no need for a whole new ZTNA, NAC, or other LMNOP product.

•	Flexible and extensible. Though described for VPNs, the same approach can be applied to other network edges and points of access. For example, you could feed the same healthy-device list into a NAC system, VDI gateway, or IdP. Any system that takes an IP allow-list can use the DEBACL feed, so your “only-known-IPs” policy can be consistently enforced across the environment.


#### Closing Thoughts

Start small by simulating DEBACL using your existing data. For example, pull the list of managed endpoint IPs from your EDR or inventory database and compare it against recent VPN logins. Any successful VPN login from an IP not on your known-device list could be a red flag: it likely represents an unmanaged, unknown, or compromised machine that shouldn’t have access. Similarly, ensure all VPN authentication attempts are centrally logged so you can monitor who is getting blocked. This simple log analysis will highlight gaps – for instance, it might reveal old, unmanaged devices or home PCs using valid credentials. Those insights show exactly where DEBACL would pay off by denying those logins outright. Before you know it there may be opportunities to DEBACLFI (DEBACL for IdPs).
In summary, DEBACL leverages the data you already have on endpoint health to dramatically shrink the VPN’s exposure. It’s like giving your VPN gateway a secret guest list that changes in real time – only “invited” (known-good) devices ever get through. Try overlaying a dynamic allow-list onto VPNs in monitor-mode and see which logins fall outside it. This exercise alone can uncover unmanaged or risky devices still getting in and makes a compelling case for moving toward a full DEBACL implementation.
