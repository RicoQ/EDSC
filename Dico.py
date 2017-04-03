#! usr/bin/python
#-*- coding: utf-8 -*-
from scapy.all import *

#This file is not done and needs lots ans lots of work

#ShittyAddress=[     #Addresses to be banned (mostly Microsoft backdoor spyware) 
  #(134.170.30.202
  #"137.116.81.24"
  #"204.79.197.200"
  #"23.218.212.69"
  #"65.39.117.230"
  #"65.55.108.23"
  #"a-0001.a-msedge.net"
  #"choice.microsoft.com"
  #"choice.microsoft.com.nsatc.net"
  #"compatexchange.cloudapp.net"
  #"corp.sts.microsoft.com"
  #"corpext.msitadfs.glbdns2.microsoft.com" 
  #"cs1.wpc.v0cdn.net"
  #"df.telemetry.microsoft.com"
  #"diagnostics.support.microsoft.com"
  #"fe2.update.microsoft.com.akadns.net"
  #"feedback.microsoft-hohm.com"
  #"feedback.search.microsoft.com"
  #"feedback.windows.com"
  #"i1.services.social.microsoft.com"
  #"i1.services.social.microsoft.com.nsatc.net"
  #"oca.telemetry.microsoft.com"
  #"oca.telemetry.microsoft.com.nsatc.net"
  #"pre.footprintpredict.com"
  #"redir.metaservices.microsoft.com"
  #"reports.wes.df.telemetry.microsoft.com"
  #"services.wes.df.telemetry.microsoft.com"
  #"settings-sandbox.data.microsoft.com"
  #"sls.update.microsoft.com.akadns.net"
  #"sqm.df.telemetry.microsoft.com"
  #"sqm.telemetry.microsoft.com"
  #"sqm.telemetry.microsoft.com.nsatc.net"
  #"statsfe1.ws.microsoft.com"
  #"statsfe2.update.microsoft.com.akadns.net"
  #"statsfe2.ws.microsoft.com"
  #"survey.watson.microsoft.com"
  #"telecommand.telemetry.microsoft.com"
  #"telecommand.telemetry.microsoft.com.nsatc.net"
  #"telemetry.appex.bing.net"
  #"telemetry.appex.bing.net:443"
  #"telemetry.microsoft.com"
  #"telemetry.urs.microsoft.com"
  #"vortex.data.microsoft.com"
  #"vortex-sandbox.data.microsoft.com"
  #"vortex-win.data.microsoft.com"
  #"watson.live.com"
  #"watson.microsoft.com"
  #"watson.ppe.telemetry.microsoft.com"
  #"watson.telemetry.microsoft.com"
  #"watson.telemetry.microsoft.com.nsatc.net"
  #"wes.df.telemetry.microsoft.com")]

NTPserveurList=[("193.190.230.65" , "NTP Server {ntp1.oma.be}"), 	#ntp1.oma.be
		("178.32.80.7"    , "NTP Server {ntp.crazyblock}"), 	#ntp.crazyblock-network.net
		("62.210.85.244"  , "NTP Server {kitty.zeroloop}"), 	#kitty.zeroloop.net
		("213.251.128.249", "NTP Server {ntp0.ovh.net}"),   	#ntp0.ovh.net
		("209.51.161.238" , "NTP Server {clock.nyc.he.net"),   	#clock.nyc.he.net
		("63.145.169.3"   , "NTP Server {gpstime.la}"),        	#gpstime.la-archdiocese.net
		("128.252.19.1"   , "NTP Server {navobs1.wustl.edu"),] 	#navobs1.wustl.edu

ARPTypes=[("0","Reserved"), 	("1","REQUEST"), 	("2","REPLY"),		("3","request Reverse"),
	("4","reply Reverse"),	("5","DRARP-Request"),	("6","DRARP-Reply"),	("7","DRARP-Error"),
	("8","InARP-Request"),	("9","InARP-Reply"),	("10","ARP-NAK"),	("11","MARS-Request"),
	("12","MARS-Multi"),	("13","MARS-MServ"),	("14","MARS-Join"),	("15","MARS-Leave"),
	("16","MARS-NAK"),	("17","MARS-Unserv"),	("18","MARS-SJoin"),	("19","MARS-SLeave"),
	("20","MARS-Grouplist-Request"),	("21","MARS-Grouplist-Reply"),	("22","MARS-Redirect-Map"),
	("23","MAPOS-UNARP"),	("24","OP_EXP1"),	("25","OP_EXP2")]

EthTypes=[(hex(0x0800),"IPv4"), (hex(0x0806),"ARP"),            (hex(0x0842),"Wake-on-Lan"),
	(hex(0x22f3),"IETF"),           (hex(0x6003),"DECnet"),         (hex(0x8035),"Reverse ARP"),
        (hex(0x80f3),"AppleTalk(ARP)"), (hex(0x8100),"VLAN-Tagged"),    (hex(0x809b),"AppleTalk(Ethertalk)"),
        (hex(0x8137),"IPX"),            (hex(0x8204),"QNX Qnet"),       (hex(0x86dd),"IPv6"),
        (hex(0x88cc),"LLDP"),           (hex(0x8808),"Ethernet Flow"),  (hex(0x8819),"CobraNet"),
        (hex(0x8847),"MPLS Unicast"),   (hex(0x8848),"MPLS Multicast"), (hex(0x8863),"PPPoE Dicovey"),
        (hex(0x8864),"PPPoE Session"),  (hex(0x8870),"Jumbo Frames"),   (hex(0x887b),"HomePlug MME"),
        (hex(0x888e),"ERP over Lan",),  (hex(0x8892),"Pofinet"),        (hex(0x889a),"hyperSCSI"),
        (hex(0x88a4),"EtherCat"),       (hex(0x88e3),"MRP"),            (hex(0x88a2),"ATA over Ethernet"),
        (hex(0x88cd),"SERCOS III"),     (hex(0x88e5),"MAC Security"),   (hex(0x88a8),"Provider Bridging"),
        (hex(0x88e1),"HomePlug AV MME"),(hex(0x88e7),"PBB"),            (hex(0x88ab),"Ethernet PowerLink"),
        (hex(0x88f7),"PTP"),            (hex(0x8902),"CFM"),            (hex(0x8906),"FCoE"),
        (hex(0x8914),"FCoE ini"),       (hex(0x8915),"RoCE"),           (hex(0x892f),"HSR"),
        (hex(0x9000),"Ethernet Test")]

ProtoTypes=[(hex(0x00),"HOPOPT"),(hex(0x01),"ICMP"),            (hex(0x02),"IGMP"),             (hex(0x03),"GGP"),
	(hex(0x04),"IP-in-IP"),         (hex(0x05),"IST"),              (hex(0x06),"TCP"),              (hex(0x07),"CBT"),
        (hex(0x08),"EGP"),              (hex(0x09),"IGP"),              (hex(0x23),"IDPR"),             (hex(0x0A),"BBN-RCC-MON"),
        (hex(0x0B),"NVP-II"),           (hex(0x0C),"PUP"),              (hex(0x0D),"ARGUS"),            (hex(0x0E),"EMCON"),
        (hex(0x0F),"XNET"),             (hex(0x10),"CHAOS"),            (hex(0x11),"UDP"),              (hex(0x12),"MUX"),
        (hex(0x13),"DCN-MEAS"),         (hex(0x14),"HMP"),              (hex(0x15),"PRM"),              (hex(0x16),"XNS-IDP"),
        (hex(0x17),"TRUNK-1"),          (hex(0x18),"TRUNK-2"),          (hex(0x19),"LEAF-1"),           (hex(0x1A),"LEAF-2"),
        (hex(0x1B),"RDP"),              (hex(0x1C),"IRTP"),             (hex(0x1D),"ISO-TP4"),          (hex(0x1E),"NETBLT"),
        (hex(0x28),"IL"),               (hex(0x1F),"MFE-NSP"),          (hex(0x20),"MERIT-INP"),        (hex(0x21),"DCCP"),
        (hex(0x22),"3PC"),              (hex(0x24),"XTP"),              (hex(0x25),"DDP"),              (hex(0x26),"IDPR-CMTP"),
        (hex(0x27),"TP++"),             (hex(0x29),"IPv6"),             (hex(0x2A),"SDRP"),             (hex(0x2B),"IPv6-Route"),
        (hex(0x2C),"IPv6-Frag"),        (hex(0x2D),"IDRP"),             (hex(0x2E),"RSVP"),             (hex(0x2F),"GRE"),
        (hex(0x30),"MHRP"),             (hex(0x31),"BNA"),              (hex(0x32),"ESP"),              (hex(0x33),"AH"),
        (hex(0x34),"I-NLSP"),           (hex(0x35),"SWIPE"),            (hex(0x36),"NARP"),             (hex(0x37),"MOBILE IP"),
        (hex(0x38),"TLSP"),             (hex(0x39),"SKIP"),             (hex(0x3A),"IPv6-ICMP"),        (hex(0x3B),"IPv6-NoNxt"),
        (hex(0x3C),"IPv6-Opts"),        (hex(0x3D),"Any host internal protocol"),                       (hex(0x3F),"Any local network"),
        (hex(0x3E),"CFTP"),             (hex(0x40),"SAT-EXPAK"),        (hex(0x41),"KRYPTOLAN"),        (hex(0x42),"RVD"),
        (hex(0x43),"IPPC"),             (hex(0x44),"Distri. File System"),                              (hex(0x45),"SAT-MON"),
        (hex(0x46),"VISA"),             (hex(0x47),"IPCU"),             (hex(0x48),"CPNX"),             (hex(0x49),"CPHB"),
        (hex(0x4A),"WSN"),              (hex(0x4B),"PVP"),              (hex(0x4C),"BRSAT-MON"),        (hex(0x4D),"SUN-ND"),
        (hex(0x4E),"WB-MON"),           (hex(0x4F),"WB-EXPAK"),         (hex(0x50),"ISO-IP"),           (hex(0x51),"VMTP"),
        (hex(0x52),"SECURE-VMTP"),      (hex(0x53),"VINES"),            (hex(0x54),"TTP"),              (hex(0x54),"IPTM"),
        (hex(0x5F),"MICP"),             (hex(0x55),"NSFNET-IGP"),       (hex(0x56),"DGP"),              (hex(0x57),"TCF"),
        (hex(0x58),"EIGRP"),            (hex(0x59),"OSPF"),             (hex(0x60),"SCC-SP"),           (hex(0x5A),"Sprite-RPC"),
        (hex(0x5B),"LARP"),             (hex(0x5C),"MTP"),              (hex(0x5D),"AX.25"),            (hex(0x5E),"IPIP"),
        (hex(0x65),"IFMP"),             (hex(0x61),"ETHERIP"),          (hex(0x62),"ENCAP"),            (hex(0x63),"Private Encryption Scheme"),
        (hex(0x64),"GMTP"),             (hex(0x71),"PGM"),              (hex(0x66),"PNNI"),             (hex(0x67),"PIM"),
        (hex(0x68),"ARIS"),             (hex(0x69),"SCPS-TP-1"),        (hex(0x6A),"QNX"),              (hex(0x6D),"SNP"),
        (hex(0x6B),"Active Networks"),  (hex(0x6C),"IPComp"),           (hex(0x6E),"Compaq-Peer"),      (hex(0x6F),"IPX-in-IP"),
        (hex(0x70),"VRRP"),             (hex(0x72),"0-hop-protocol"),   (hex(0x73),"L2TP"),             (hex(0x74),"DDX D-II"),
        (hex(0x75),"IATP"),             (hex(0x76),"STP"),              (hex(0x77),"SRP"),              (hex(0x78),"UTI"),
        (hex(0x79),"SMP"),              (hex(0x7A),"SM-03"),            (hex(0x7B),"PTP"),              (hex(0x7C),"IS-IS over IPv4"),
        (hex(0x7D),"FIRE"),             (hex(0x7E),"CRTP"),             (hex(0x7F),"CRUDP"),            (hex(0x80),"SSCOPMCE"),
        (hex(0x81),"IPLT"),             (hex(0x82),"SPS"),              (hex(0x83),"PIPE"),             (hex(0x84),"SCTP"),
        (hex(0x85),"FC"),               (hex(0x86),"RSVP-E2E-IGNORE"),  (hex(0x87),"Mobility Header"),  (hex(0x88),"UDP-Lite"),
        (hex(0x89),"MPLS-in-IP"),       (hex(0x8A),"MANET Protocols"),  (hex(0x8B),"HIP"),              (hex(0x8C),"Shim6"),
        (hex(0x8D),"WESP"),             (hex(0x8E),"ROHC"),             (hex(0xFF),"Reserved")]
        ##(hex(0x8F-0xFC),"UNASSIGNED"),
        ##(hex(0xFD-0xFE),"Experimentation & Testing")

	## 9 sctp Discard
	## 9 dccp Discard

PortCur=[("22","Putty"),
	 ("40500","Pop-Corn"),
	 ("1","TCP Port Service Multiplexer (TCPMUX)"),
	 ("5","Remote Job Entry (RJE)"),
	 ("7","ECHO"),
	 ("18","Message Send Protocol (MSP)"),
	 ("20","FTP [Default Data]"),
	 ("21","FTP [Control]"),
	 #("22","SSH"), #= "Secure Shell Remote Login Protocol"
	 ("23","TELNET"),
	 ("25","Simple Mail Transfer Protocol (SMTP)"),
	 ("29","MSG ICP"),
 	 ("37","Time"),
	 ("42","Host Name Server (NameServ)"),
   #("43","WhoIs"),
	 ("49","Login Host Protocol (Login)"),
	 ("53","Domain Name System (DNS)"),
	 #("69","Trivial File Transfer Protocol (TFTP)"),
	 ("70","Gopher Services"),
   ("79","Finger"),
	 ("80","Http"),
	 ("103","X.400 Standard"),
	 ("108","SNA Gateway Access Server"),
	 ("109","POP2"),
	 ("110","POP3"),
 	 ("115","Simple File Transfer Protocol (SFTP)"),
	 ("118","SQL Services"),
 	 ("119","Newsgroup (NNTP)"),
 	 ("137","NetBIOS Name Service"), # = Official
	 ("138","NetBIOS Datagram Service"), # = Official
 	 ("139","NetBIOS Session Service"), # = Official
	 ("143","Interim Mail Access Protocol (IMAP)"),
 	 #("150","???"), # = need to find a decriptif for this port
 	 ("156","SQL Server"),
 	 ("161","SNMP"),
 	 ("179","Border Gateway Protocol (BGP)"),
 	 ("190","Gateway Access Control Protocol (GACP)"),
 	 ("194","Internet Relay Chat (IRC)"),
 	 ("197","Directory Location Service (DLS)"),
 	 ("389","Lightweight Directory Access Protocol (LDAP)"),
	 ("396","Novell Netware over IP"),
	 ("443","Https"),
	 ("444","Simple Network Paging Protocol (SNPP)"),
	 ("445","Microsoft-DS AD, Windows shares & SMB"), # = Official
	 ("458","Apple QuickTime"),
	 ("546","DHCPv6 Client"),
	 ("547","DHCPv6 Server"),
	 ("563","NNTP over TLS/SSL (NNTPS)"), # = Official
	 ("569","MSN"),
	 ("1080","Socks (Proxy)"),
	 ("5228","Chrome User Data Sync")]

PortUnCur=[("0","Reserved"),
	   ("2","compressnet - Management Utility"),
	   ("3","compressnet - Compression Process"),
	   ("4","Unassigned"),
	   ("6","Unassigned"),
	   ("8","Unassigned"),
	   ("9","discard - Discard"),
	   ("10","Unassigned"),
	   ("11","systat - Active Users"),
	   ("12","Unassigned"),
	   ("13","Daytime"),
	   ("14","Unassigned"),
	   ("15","Unassigned"),
	   ("16","Unassigned"),
	   ("17","qotd - Quote of the Day"),
	   ("19","Character Generator"),
	   #("20","FTP [Default Data]"), #("[Default Data] File Transfer"),
	   #("21","FTP [Control]"), #("[Control] File Transfer"), # = Defined keys: u=<username> p=<password> path=<path>
	   #("22","SSH"), #("The Secure Shell (SSH)"), # = Defined keys: u=<username> p=<password>
	   #("23","Telnet"), # = Defined keys: u=<username> p=<password>
	   ("24","private mail system"),
	   #("25","SMTP"), #Simple Mail Transfer
	   ("26","Unassigned"),
	   ("27","NSW User System FE"),
	   ("28","Unassigned"),
	   #("29","MSG ICP"),
	   ("30","Unassigned"),
	   ("31","MSG Authentication"),
	   ("32","Unassigned"),
	   ("33","Display Support"),
	   ("34","Unassigned"),
	   ("35","private printer server"),
	   ("36","Unassigned"),
	   #("37","Time"),
	   ("38","Route Access"),
	   ("39","Resource Location Protocol"),
	   ("40","Unassigned"),
	   ("41","Graphics"),
	   #("42","Host Name Server"),
	   ("43","nicname -'Who Is'"),
	   ("44","MPM FLAGS Protocol"), #Message Processing Module
	   ("45","MPM [recv]"), #Message Processing Module
	   ("46","MPM [default send]"), #Message Processing Module
	   ("47","FTP [NI]"),
	   ("48","Digital Audit Daemon"),
	   #("49","Login Host Protocol (TACACS)"),
	   ("50","Remote Mail Checking Protocol"),
	   ("51","Reserved"),  #This entry was removed on 2013-05-24.
	   ("52","XNS Time Protocol"),
	   ("54","XNS Clearinghouse"),
	   ("55","ISI Graphics Language"),
	   ("56","XNS Authentication"),
	   ("57","Private Terminal Access"),
	   ("58","XNS Mail"),
	   ("59","Private File Service"),
	   ("60","Unassigned"),
	   ("61","MAIL [NI]"),
	   ("62","ACA Services"), #(whois++)
	   ("63","whoispp"), #IANA assigned this name as a replacement for "whois++".
	   #("63","whois++"), # = "whois++ historic, not usable for use with many common service discovery mechanisms."
	   ("64","Communications Integrator (CI)"),
	   ("65","TACACS-Database Service"),
	   ("66","sql-net"), # IANA assigned this service name as replacement for "sql*net".
           #("66","sql*net"), # Discovery mechanisms Oracle SQL*NET historic, not usable with many common service
	   ("67","Bootstrap Protocol Server"), #Defined TXT keys: None
	   ("68","Bootstrap Protocol Client"),
	   ("69","T-FTP [Trivial File Transfer]"),
	   #("70","Gopher"),
	   ("71","netrjs-1 [Remote Job Service 1]"),
	   ("72","netrjs-2 [Remote Job Service 2]"),
	   ("73","netrjs-3 [Remote Job Service 3]"),
	   ("74","netrjs-4 [Remote Job Service 4]"),
	   ("75","Private Dial Out Service"),
	   ("76","Distributed External Object Store"),
	   ("77","Private RJE Service"),
	   ("78","vettcp"),
	   #("79","Finger"), #mail users (see [RFC4146] for details) Caution! = Unauthorized use by some
	   #("79","finger"), #UDP = Finger -- mail usersmicrosoft-dsmicrosoft-ds
	   ("81","Torpark onion routing"), # = Unofficial
	   ("82","Torpark control"), # = Unofficial
	   ("88","Kerberos authentication system"), # = Official
	   ("90","dnsix [DoD Network Security]"), #For Information Exchange, Security Attribute Token Map = Official
	   #("90","PointCast UDP Only), # = Unofficial
	   ("99","WIP Message protocol"), # = Unofficial
	   ("100","(UDP only) CyberGate RAT protocol"), # = Unofficial
	   ("101","NIC host name"), # = Official
	   ("102","ISO Transport Service Access Point (TSAP)"), # Also used by Digital Equipment Corporation DECnet (Phase V+) over TCP/IP = Official
	   ("104","ACR/NEMA (DICOM)"), # = Official
	   ("105","CCSO NameServer (Qi/Ph)"), # = Official
	   ("107","Remote Telnet Service"), # = Official
	   ("111","ONC RPC (Sun RPC)"), # = Official
	   ("113","IRC (Ident & auth service)"), # = Official
	   ("117","STD - UUCP Path Service"), # = Official
	   ("123","Network Time Protocol (NTP)"), # = Official
	   ("126","NXEdit"), # = Official  #Used by Unisys Programmer's Workbench for Clearpath MCP, an IDE for Unisys MCP software development
	   ("135","DCE endpoint resolution"), # = Official
	   ("135","Microsoft EPMAP (End Point Mapper)"), # = Unofficial #used to remotely manage services (DHCP server, DNS server and WINS. Also used by DCOM
	   ("152","Background File Transfer (BFTP)"), # = Official
	   ("153","Simple Gateway Monitoring (SGMP)"), # = Official
	   ("158","Distributed Mail Service (DMSP)"), # = Unofficial
	   ("162","Simple Network Management (SNMPTRAP)"), # = Official
	   ("170","Print-srv, Network PostScript"), # = Official
	   ("175","VMNET"), # = Official   #(IBM z/VM, z/OS & z/VSE—Network Job Entry (NJE))
	   ("177","X Display Manager Control (XDMCP)"), # = Official
	   ("199","SMUX, SNMP Unix Multiplexer"), # = Official
	   ("201","AppleTalk Routing Maintenance"), # = Official
	   ("209","QMTP"), #"Quick Mail Transfer Protocol"), # = Official
	   ("210","ANSI Z39.50"), # = Official
	   ("213","IPX"),	#"Internetwork Packet Exchange (IPX)"), # = Official
	   ("218","MPP"), 	#"Message posting protocol (MPP)"),	# = Official
   	   ("220","IMAPv3"),	#"Internet Message Access Protocol (IMAP)"), version 3 # = Official
 	   ("259","ESRO"),	#"Efficient Short Remote Operations (ESRO)"), # = Official
	   ("262","Arcisdms"),  # = Official
	   ("264","BGMP"), 	#"Border Gateway Multicast Protocol (BGMP)"), # = Official
 	   ("280","http-mgmt"), # = Official
	   ("300","TLWA"),	#"ThinLinc Web Access"), # = Unofficial
	   ("308","Novastor Online Backup"), # = Official
	   ("311","Mac OS X Server Admin"), #(officially AppleShare IP Web administration) # = Official
	   ("318","TSP"), #"PKIX Time Stamp Protocol (TSP)"), # = Official
	   ("319","PTP [Event Msg]"), #"Precision Time Protocol (PTP) event messages"), # = Official
	   ("320","PTP [General Msg]"), #"Precision Time Protocol (PTP) general messages"), # = Official
	   ("350","MATIP [Type A]"), #"Mapping of Airline Traffic over Internet Protocol (MATIP) type A"), # = Official
	   ("351","MATIP [Type B]"), #"Mapping of Airline Traffic over Internet Protocol (MATIP) type B"), # = Official
	   ("356","cloanto-net-1"), #"Cloanto Amiga Explorer and VMs)"), # = Official
	   ("366","ODMR"), #"On-Demand Mail Relay (ODMR)"), # = Official
	   ("369","Rpc2portmap"), # = Official
	   ("370","codaauth2"), #"Coda authentication server"), # = Official
	   ("370","securecast1"), #outgoing packets to NAI's SecureCast servers, as of 2000 # = Unofficial
	   ("371","ClearCase albd"), # = Official
	   ("383","HP data alarm manager"), # = Official
	   ("384","Remote Network Server System"), # = Official
	   ("387","AURP"), #"(AppleTalk Update-based Routing Protocol)"), # = Official
	   ("399","DECnet [Phase V+]"), #"Digital Equipment Corporation DECnet (Phase V+) over TCP/IP" # = Official
	   ("401","UPS"), #"Uninterruptible power supply (UPS)"), # = Official
	   ("427","SLP"), #"Service Location Protocol (SLP)"), # = Official
	   ("433","NNSP"), #"Network News Transfer Protocol"), # = Official
	   ("434","Mobile IP Agent"), # = Official
	   ("443","QUIC"), #(from Chromium) for HTTPS # = Unofficial
	   ("464","Kerberos [PWD Management]"), #"Kerberos Change/Set password"), # = Official
	   ("465","Cisco protocol [SSM]"),	#"URL Rendezvous Directory for SSM (Cisco protocol)"), # = Official
	   ("465","SMTPS"), #"Simple Mail Transfer Protocol over TLS/SSL (SMTPS)"), # = Unofficial
	   ("475","tcpnethaspsrv"), #"Aladdin Knowledge Systems Hasp services"), # = Official
	   #("491","	TCP		GO-Global remote access and application publishing software	Unofficial
	   #("497","	TCP		Dantz Retrospect	Official
	   ("500","ISAKMP & IKE"), #"Internet Security Association and Key Management Protocol (ISAKMP) & Internet Key Exchange (IKE)"), # = Official
	   #("502","	TCP	UDP	Modbus Protocol	Official
     	   #("504","	TCP	UDP	Citadel, multiservice protocol for dedicated clients for the Citadel groupware system	Official
	   #("510","	TCP	UDP	FirstClass Protocol (FCP), used by FirstClass client/server groupware system	Official
	   #("512","	TCP		Rexec, Remote Process Execution	Official
  	   #("512","		UDP	comsat, together with biff	Official
	   #("513","	TCP		rlogin	Official
	   #("513","		UDP	Who[23]	Official
	   #("514","		Remote Shell, used to execute non-interactive commands on a remote system (Remote Shell, rsh, remsh)	Official
	   #("514","		UDP	Syslog, used for system logging	Official
	   ("515","LPD"), #"Line Printer Daemon (LPD), print service"), # = Official
	   #("517","		UDP	Talk	Official
	   #("518","		UDP	NTalk	Official
 	   #("520","	TCP		efs, extended file name server	Official
	   ("520","RIP"), #"Routing Information Protocol (RIP)" # = Official
	   ("521","RIPng"), #"Routing Information Protocol Next Generation (RIPng)" # = Official
	   ("524","NetWare Core Protocol"), #(NCP) is used for NetWare server resources, Time Sync, etc. # = Official
	   #("525","		UDP	Timed, Timeserver	Official
	   #("530","	TCP	UDP	Remote procedure call (RPC)	Official
 	   #("531","	TCP	UDP	AOL Instant Messenger	Unofficial
	   #("532","	TCP		netnews	Official
	   #("533","		UDP	netwall, For Emergency Broadcasts	Official
	   ("540","UUCP"), #"Unix-to-Unix Copy Protocol (UUCP)"), # = Official
	   #("542","	TCP	UDP	commerce (Commerce Applications)	Official
 	   #("543","	TCP		klogin, Kerberos login	Official
	   #("544","	TCP		kshell, Kerberos Remote shell	Official
	   #("545","	TCP		OSIsoft PI (VMS), OSISoft PI Server Client Access	Unofficial
	   #("548","	TCP		Apple Filing Protocol (AFP) over TCP	Official
	   #("550","	TCP	UDP	new-rwho, new-who[23]	Official
	   ("554","Real Time Streaming"), #"Real Time Streaming Protocol (RTSP)"), # = Official
	   #("556","	TCP		Remotefs, RFS, rfs_server	Official
	   #("560","		UDP	rmonitor, Remote Monitor	Official
	   #("561","		UDP	monitor	Official
	   #("564","	TCP		9P (Plan 9)	Unofficial
	   #("587","	TCP		e-mail message submission[24] (SMTP)	Official
	   ("591","FileMaker 6.0"), #"FileMaker 6.0 (and later) Web Sharing (HTTP Alternate)"), # = Official
	   ("593","HTTP RPC Ep Map"), #Remote procedure call over Hypertext Transfer Protocol, often used by Microsoft Exchange Server # = Official
	   #("601","	TCP		Reliable Syslog Service — used for system logging	Official
	   #("604","	TCP		TUNNEL profile,[25] a protocol for BEEP peers to form an application layer tunnel	Official
	   #("623","		UDP	ASF Remote Management and Control Protocol (ASF-RMCP)	Official
	   ("625","ODProxy"), #"Open Directory Proxy (ODProxy)"), # = Unofficial
	   #("631","	TCP	UDP	Internet Printing Protocol (IPP)	Official
	   #("631","	TCP	UDP	Common Unix Printing System (CUPS) administration console (extension to IPP)	Unofficial
	   #("635","	TCP	UDP	RLZ DBase	Official
	   #("636","	TCP	UDP	Lightweight Directory Access Protocol over TLS/SSL (LDAPS)	Official
	   ("639","MSDP"), #"Multicast Source Discovery Protocol"), # = Official
	   #("641","	TCP	UDP	SupportSoft Nexus Remote Command (control/listening), a proxy gateway connecting remote control traffic	Official
	   #("643","	TCP	UDP	SANity	Official
	   ("646","LDP"), #"Label Distribution Protocol (LDP)"), #routing protocol used in MPLS networks # =Official
	   #("647","	TCP		DHCP Failover protocol[26]	Official
	   #("648","	TCP		Registry Registrar Protocol (RRP)[27]	Official
	   #("651","	TCP	UDP	IEEE-MMS	Official
	   #("653","	TCP	UDP	SupportSoft Nexus Remote Command (data), a proxy gateway connecting remote control traffic	Official
	   ("654","MMS & MMP"), #"Media Management System (MMS) & Media Management Protocol (MMP)"), # = Official
	   #("655","	TCP	UDP	Tinc VPN daemon	Unofficial
	   #("657","	TCP	UDP	IBM RMC (Remote monitoring and Control) protocol, used by System p5 AIX Integrated Virtualization Manager (IVM)[29] and Hardware Management Console to connect managed logical partitions (LPAR) to enable dynamic partition reconfiguration	Official
 	   #("660","	TCP		Mac OS X Server administration	Official
	   #("666","	TCP	UDP	Doom, first online first-person shooter	Official
	   #("666","	TCP		airserv-ng, aircrack-ng's server for remote-controlling wireless devices	Unofficial
	   #("674","	TCP		Application Configuration Access Protocol (ACAP)	Official
	   #("688","	TCP	UDP	REALM-RUSD (ApplianceWare Server Appliance Management Protocol)	Official
	   #("690","	TCP	UDP	Velneo Application Transfer Protocol (VATP)	Official
	   ("691","MS Exchange Routing"), # = Official
	   #("694","	TCP	UDP	Linux-HA high-availability heartbeat	Official
	   ("695","IEEE over SSL"), #"IEEE Media Management System over SSL (IEEE-MMS-SSL)" # = Official
	   ("698","OLSR"), #"Optimized Link State Routing (OLSR)"), # = Official
	   ("700","EPP"),  #"Extensible Provisioning Protocol (EPP)"), a protocol for communication between domain name registries and registrars # = Official
	   ("701","LMP"),  #"Link Management Protocol (LMP)"), #protocol that runs between a pair of nodes and is used to manage traffic engineering (TE) # = Official
	   ("702","IRIS over BEEP"), #IRIS (Internet Registry Information Service) over BEEP (Blocks Extensible Exchange Protocol) # = Official
	   ("706","SILC"), #"Secure Internet Live Conferencing (SILC)"), # = Official
	   #("711","	TCP		Cisco Tag Distribution Protocol[35][36][37]—being replaced by the MPLS Label Distribution Protocol[38]	Official
	   #("712","	TCP		Topology Broadcast based on Reverse-Path Forwarding routing protocol (TBRPF; RFC 3684)	Official
	   #("749","	TCP	UDP	Kerberos (protocol) administration	Official
	   #("750","		UDP	kerberos-iv, Kerberos version IV	Official
	   #("751","	TCP	UDP	kerberos_master, Kerberos authentication	Unofficial
	   #("752","		UDP	passwd_server, Kerberos password (kpasswd) server	Unofficial
	   #("753","	TCP		Reverse Routing Header (RRH)[39]	Official
	   #("753","		UDP	Reverse Routing Header (RRH)	Official
	   #("753","		UDP	userreg_server, Kerberos userreg server	Unofficial
	   #("754","	TCP		tell send	Official
	   #("754","	TCP		krb5_prop, Kerberos v5 slave propagation	Unofficial
	   #("754","		UDP	tell send	Official
	   #("760","	TCP	UDP	krbupdate [kreg], Kerberos registration	Unofficial
	   #("782","	TCP		Conserver serial-console management server	Unofficial
	   #("783","	TCP		SpamAssassin spamd daemon	Unofficial
	   #("800","	TCP	UDP	mdbs-daemon	Official
	   #("808","	TCP		Microsoft Net.TCP Port Sharing Service	Unofficial
	   #("829","	TCP		Certificate Management Protocol[40]	Unofficial
 	   #("830","	TCP	UDP	NETCONF over SSH	Official
	   #("831","	TCP	UDP	NETCONF over BEEP	Official
	   #("832","	TCP	UDP	NETCONF for SOAP over HTTPS	Official
	   #("833","	TCP	UDP	NETCONF for SOAP over BEEP	Official
	   #("843","	TCP		Adobe Flash[41]	Unofficial
 	   ("847","DHCP Failover"), #"DHCP Failover protocol"), # = Official
	   #("848","	TCP	UDP	Group Domain Of Interpretation (GDOI) protocol	Official
	   #("860","	TCP		iSCSI (RFC 3720)	Official
	   #("861","	TCP	UDP	OWAMP control (RFC 4656)	Official
	   #("862","	TCP	UDP	TWAMP control (RFC 5357)	Official
	   #("873","	TCP		rsync file synchronization protocol	Official
	   #("888","	TCP		cddbp, CD DataBase (CDDB) protocol (CDDBP)	Unofficial
	   #("888","	TCP		IBM Endpoint Manager Remote Control	Unofficial
	   #("897","	TCP	UDP	Brocade SMI-S RPC	Unofficial
	   #("898","	TCP	UDP	Brocade SMI-S RPC SSL	Unofficial
	   #("901","	TCP		Samba Web Administration Tool (SWAT)	Unofficial
	   #("901","	TCP	UDP	VMware Virtual Infrastructure Client (from managed device to management console)	Unofficial
	   #("902","	TCP	UDP	ideafarm-door (IdeaFarm (tm) Operations)	Official
	   #("902","	TCP	UDP	VMware Server Console (from management console to managed device)	Unofficial
	   #("903","	TCP	UDP	ideafarm-panic (IdeaFarm (tm) Operations)	Official
	   #("903","	TCP		VMware Remote Console[42]	Unofficial
	   #("904","	TCP		VMware Server alternate	Unofficial
	   #("911","	TCP		Network Console on Acid (NCA), local tty redirection over OpenSSH	Unofficial
	   ("944","Network File System Service"), # = Unofficial
	   ("953","DNS"), #"Domain Name System (DNS) RNDC Service"), # = Unofficial
	   ("973","Network File System over IPv6 Service"), # = Unofficial
	   #("981","Remote HTTPS management"),	= SofaWare Technologies Remote HTTPS management for firewall devices running embedded Check Point FireWall-1 software	Unofficial
	   ("987","MS SBS SharPoint"), #"Microsoft Windows SBS SharePoint"), # = Unofficial
	   ("989","FTPS [Data]"), #"FTPS Protocol (data), FTP over TLS/SSL"), # = Official
	   ("990","FTPS [Control]"), #"FTPS Protocol (control), FTP over TLS/SSL"), # = Official
 	   ("991","NAS"), #Netnews Administration System (NAS)"), # = Official
	   ("992","TelNet over TLS-SSL"), #"Telnet protocol over TLS/SSL"), # = Official
	   ("993","IMPAS"), #"Internet Message Access Protocol over TLS/SSL (IMAPS)"), # = Official
	   ("994","IRCS"), #"Internet Relay Chat over TLS/SSL (IRCS)"), # = Official
	   ("995","POP3S"), #"Post Office Protocol 3 over TLS/SSL (POP3S)#), # = Official
	   ("999","ScimoreDB Database System"), # = Unofficial
	   #("1002","	TCP		Opsware agent (aka cogbot)	Unofficial
	   #("1010","	ThinLinc Web Administration	Unofficial
	   ("1023","Reserved"), # = Official
	   ("99999","Make-Shift Dict Entry"] # = Make-Shift Dict Entry to simulate the END of PortUnCur

IPv4flags=[("toto","tata")]

ICMPv6type=[("133","Router Solicitation"),
	    ("134","Router Advertisement"),
	    ("135","Neighbor Solicitation"),
	    ("136","Neighbor Advertisement"),
	    ("137","Redirect")]
