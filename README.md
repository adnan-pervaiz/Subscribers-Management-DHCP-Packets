# Subscribers-Management-DHCP-Packets
This blog is intended to illustrate FTTH subscriber access and management solution.
In this blog The FTTH subscriber access and management is based on Juniper Networks MX Broadband Service Router (BSR), Bridgewater AAA, and Cisco PM/DPI (SCE)
Broadband subscriber management is a method of dynamically provision and manage subscriber access in broadband network.
- Dynamically provision 
- Interface and access route
- Dynamically manage
- Gather usage statistics (ingress/egress)

There are 2 access protocols for subscriber management
- PPP
- DHCP
Each of the above access protocols provides all required network parameters to the subscriber dynamically
- IP address, subnet mask
- DNS
How the network knows the subscriber identity to accept his access request ?
- PPP defines standard Authentication mechanism (PAP, CHAP)
- DHCP doesn't define standard authentication (per implementation)
- Subscriber intially is anonymous, then authenticate via portal (Hotspot)
- Ethernet dot1X authentication (Enterprise)
- Create subscriber credentials from DHCP discover message (JUNOS way)
–	Subscriber MAC address (Source MAC address of DHCP request)
–	DHCP option 82 (Agent Circuit ID = DSLAM port)
–	DHCP option 60 (Vendor ID, CPE serail number)

Subscriber Management DHCP Based

![image](https://github.com/user-attachments/assets/0fda2f93-53f3-41da-bd79-eaae47b65a7c)

We have to understand in deep DHCP packets for subscribers management ,below is packet capture for DHCP during the communication testing.

DHCP Packet sniffing (DHCP Discover)

 	In IP (tos 0x0, ttl 255, id 0, offset 0, flags [none], proto: UDP (17), length: 668) 0.0.0.0.bootpc > 255.255.255.255.bootps: BOOTP/DHCP, Request from 0:25:9e:d3:22:76, length 592, xid 0x1c60011, Flags [none]
 		  Client-Ethernet-Address 0:25:9e:d3:22:76
 		  Vendor-rfc1048 Extensions
 		    Magic Cookie 0x63825363
 		    DHCP-Message Option 53, length 1: Discover
 		    Client-ID Option 61, length 7: ether 00:25:9e:d3:22:76
 		    Vendor-Class Option 60, length 24: "snmp.mib21:huawei:HG8245"
 		    Parameter-Request Option 55, length 10: 
 		      Subnet-Mask, Default-Gateway, Domain-Name-Server, Hostname
 		      Domain-Name, BR, YD, YS
 		      NTP, Option 120
 		    Agent-Information Option 82, length 41: 
 		      Circuit-ID SubOption 1, length 37: trnt-5600-00 xpon 0/13/0/2:6.133.1333
 		      Remote-ID SubOption 2, length 0: 


DHCP Packet sniffing (DHCP OFFER)

 	Out IP (tos 0x0, ttl   1, id 59296, offset 0, flags [none], proto: UDP (17), length: 365) 82.134.106.1.bootps > 255.255.255.255.bootpc: BOOTP/DHCP, Reply, length 337, xid 0x1c60011, Flags [none]
 		  Your-IP 82.134.106.13
 		  Client-Ethernet-Address 0:25:9e:d3:22:76
 		  Vendor-rfc1048 Extensions
 		    Magic Cookie 0x63825363
 		    DHCP-Message Option 53, length 1: Offer
 		    Lease-Time Option 51, length 4: 600
 		    Server-ID Option 54, length 4: 82.134.106.1
 		    Subnet-Mask Option 1, length 4: 255.255.252.0
 		    Default-Gateway Option 3, length 4: 82.134.106.1
 		    Domain-Name-Server Option 6, length 8: 82.52.144.28,86.51.35.17
 		    Domain-Name Option 15, length 13: "abc.com.sa"
 		    Agent-Information Option 82, length 41: 
 		      Circuit-ID SubOption 1, length 37: ABC-4400-00 xpon 0/13/0/2:6.133.1333
 		      Remote-ID SubOption 2, length 0: 

DHCP Packet sniffing (DHCP REQUEST)

 	In IP (tos 0x0, ttl 255, id 0, offset 0, flags [none], proto: UDP (17), length: 668) 0.0.0.0.bootpc > 255.255.255.255.bootps: BOOTP/DHCP, Request from 0:25:9e:d3:22:76, length 592, xid 0x1c60011, Flags [none]
 		  Client-Ethernet-Address 0:25:9e:d3:22:76
 		  Vendor-rfc1048 Extensions
 		    Magic Cookie 0x63825363
 		    DHCP-Message Option 53, length 1: Request
 		    Client-ID Option 61, length 7: ether 00:25:9e:d3:22:76
 		    Vendor-Class Option 60, length 24: "snmp.mib21:huawei:HG8245"
 		    Requested-IP Option 50, length 4: 82.134.106.13
 		    Server-ID Option 54, length 4: 82.134.116.1
 		    Parameter-Request Option 55, length 10: 
 		      Subnet-Mask, Default-Gateway, Domain-Name-Server, Hostname
 		      Domain-Name, BR, YD, YS
 		      NTP, Option 120
 		    Agent-Information Option 82, length 41: 
 		      Circuit-ID SubOption 1, length 37: ABC-4400-00 xpon 0/13/0/2:6.133.1333
 		      Remote-ID SubOption 2, length 0:

DHCP Packet sniffing (DHCP REQUEST)

 	Out IP (tos 0x0, ttl   1, id 59460, offset 0, flags [none], proto: UDP (17), length: 365) 82.134.106.1.bootps > 255.255.255.255.bootpc: BOOTP/DHCP, Reply, length 337, xid 0x1c60011, Flags [none]
 		  Your-IP 78.138.216.13
 		  Client-Ethernet-Address 0:25:9e:d3:22:76
 		  Vendor-rfc1048 Extensions
 		    Magic Cookie 0x63825363
 		    DHCP-Message Option 53, length 1: ACK
 		    Lease-Time Option 51, length 4: 600
 		    Server-ID Option 54, length 4: 82.134.106.1
 		    Subnet-Mask Option 1, length 4: 255.255.252.0
 		    Default-Gateway Option 3, length 4: 82.134.106.1
 		    Domain-Name-Server Option 6, length 8: 86.51.34.17,86.51.35.17
 		    Domain-Name Option 15, length 13: "abc.com.sa"
 		    Agent-Information Option 82, length 41: 
 		      Circuit-ID SubOption 1, length 37: ABC-4400-00 xpon 0/13/0/2:6.133.1333
 		      Remote-ID SubOption 2, length 0: 

RADIUS Packet sniffing (ACCESS REQ)

 	Out IP (tos 0x0, ttl  64, id 3915, offset 0, flags [none], proto: UDP (17), length: 288) 10.228.44.122.61515 > 10.218.19.72.radius: RADIUS, length: 260
 		Access Request (1), id: 0xa1, Authenticator: 7607c3b57ecbd511e8b8b9a65fd3378a
 		  Username Attribute (1), length: 35, Value: 0025.9ed3.2276@live.abc.com.ca
 		  Password Attribute (2), length: 18, Value: 
 		  Unassigned Attribute (89), length: 3, Value: 
 		  Accounting Session ID Attribute (44), length: 6, Value: 3680
 		  Vendor Specific Attribute (26), length: 100, Value: Vendor: Unisphere Networks (4874)
 		    ERX-Dhcp-Options Attribute (55), Length: 94, Value: 5..=...%.."v<.snmp.mib21:huawei:HG82457.......()*xR).%trnt-5600-00 xpon 0/13/0/2:6.133.1333...
 		  Vendor Specific Attribute (26), length: 22, Value: Vendor: Unisphere Networks (4874)
 		    ERX-Dhcp-Mac-Addr Attribute (56), Length: 16, Value: 0025.9ed3.2276
 		  NAS ID Attribute (32), length: 18, Value: ABC-RTR1
 		  NAS Port Attribute (5), length: 6, Value: 536870929
 		  NAS Port ID Attribute (87), length: 20, Value: xe-2/0/0.17[:0-17]
 		  NAS Port Type Attribute (61), length: 6, Value: Ethernet
 		  NAS IP Address Attribute (4), length: 6, Value: 10.217.55.122

RADIUS Packet sniffing (ACCESS GRANT)

 	In IP (tos 0x0, ttl 253, id 11573, offset 0, flags [DF], proto: UDP (17), length: 117) 10.217.55.72.radius > 10.217.55.122.61515: RADIUS, length: 89
 		Access Accept (2), id: 0xa1, Authenticator: 2bbef2584a6b6b871fa66e563995fa67
 		  Class Attribute (25), length: 24, Value: BWS
 		  Vendor Specific Attribute (26), length: 19, Value: Vendor: Unisphere Networks (4874)
 		    ERX-Ingress-Policy-Name Attribute (10), Length: 13, Value: fwf_in-a-1M
 		  Vendor Specific Attribute (26), length: 12, Value: Vendor: Unisphere Networks (4874)
 		    ERX-Ingress-Statistics Attribute (12), Length: 6, Value:  1
 		  Vendor Specific Attribute (26), length: 12, Value: Vendor: Unisphere Networks (4874)
 		    ERX-Egress-Statistics Attribute (13), Length: 6, Value:  1
 		  Vendor Specific Attribute (26), length: 14, Value: Vendor: Unisphere Networks (4874)
 		    ERX-CoS-Shaping-Pmt-Type (108), Length: 6, Value:  T02 1M

RADIUS Packet sniffing (Accounting START)

 	Out IP (tos 0x0, ttl  64, id 4045, offset 0, flags [none], proto: UDP (17), length: 334) 10.217.55.122.61515 > 10.217.55.72.radacct: RADIUS, length: 306
 		Accounting Request (4), id: 0x66, Authenticator: c525fc662683dcfe440a7f8910fc8b15
 		  Username Attribute (1), length: 35, Value: 0025.9ed3.2276@abc.com.ca
 		  Accounting Status Attribute (40), length: 6, Value: Start
 		  Accounting Session ID Attribute (44), length: 6, Value: 3680
 		  Event Timestamp Attribute (55), length: 6, Value: Tue Sep 21 16:46:37 2010
 		  Framed IP Address Attribute (8), length: 6, Value: 82.134.106.87
 		  Framed IP Network Attribute (9), length: 6, Value: 255.255.255.0
 		  Vendor Specific Attribute (26), length: 19, Value: Vendor: Unisphere Networks (4874)
 		    Vendor Attribute: 10, Length: 13, Value: fwf_in-a-1M .
 		  NAS ID Attribute (32), length: 18, Value: ABC-RTR1
 		  NAS Port Attribute (5), length: 6, Value: 536870929
 		  NAS Port ID Attribute (87), length: 20, Value: xe-2/0/0.17[:0-17]
 		  NAS Port Type Attribute (61), length: 6, Value: Ethernet
 		  NAS IP Address Attribute (4), length: 6, Value: 10.217.55.122


RADIUS Packet sniffing (Accounting Update)

 	Out IP (tos 0x0, ttl  64, id 4223, offset 0, flags [none], proto: UDP (17), length: 376) 10.217.55.122.61515 > 10.218.19.72.radacct: RADIUS, length: 348
 		Accounting Request (4), id: 0x6d, Authenticator: 30e97df23fff38c1d560f02aae3b4748
 		  Username Attribute (1), length: 35, Value: 0025.9ed3.2276@abc.com.ca
 		  Accounting Status Attribute (40), length: 6, Value: Interim-Update
 		  Accounting Session ID Attribute (44), length: 6, Value: 3680
 		  Accounting Input Octets Attribute (42), length: 6, Value: 0
 		  Accounting Output Octets Attribute (43), length: 6, Value: 0
 		  Accounting Session Time Attribute (46), length: 6, Value: 01 secs
 		  Accounting Input Packets Attribute (47), length: 6, Value: 0
 		  Accounting Output Packets Attribute (48), length: 6, Value: 0
 		  Event Timestamp Attribute (55), length: 6, Value: Tue Sep 21 16:46:37 2010
 		  Framed IP Address Attribute (8), length: 6, Value: 82.134.106.87
 		  Accounting Output Giga Attribute (53), length: 6, Value: 0
 		  NAS IP Address Attribute (4), length: 6, Value: 10.217.55.122



