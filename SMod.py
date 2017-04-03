#! usr/bin/python
#-*- coding: utf-8 -*-
import itertools, threading, socket, fcntl, struct
import nmap, os, sys, time
import netifaces as nif
import Color as C

def Scan(ifname):
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        h = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', ifname[:15]))[20:24])
	return h

def V6DScan():
	V6D =[
    #("fe80::","PC-Win10"),
    #("fe80::","rpi2-Kali"),
		#("fe80::","rpi2-Raspbian"),
    #("fe80::","rpi3-LibreELEC"),
    ("ff02::1"   ,"IPv6 All-Nodes Multicast"),
		("ff02::2"   ,"IPv6 All-Routers Multicast"),
		("ff02::5"   ,"IPv6 OSPFv3 All SPF routers"),
		("ff02::6"   ,"IPv6 OSPFv3 All DR routers"),
		("ff02::8"   ,"IS-IS for IPv6 routers"),
		("ff02::9"   ,"IPv6 RIP routers"),
		("ff02::a"   ,"IPv6 EIGRP routers"),
		("ff02::d"   ,"IPv6 PIM routers"),
		("ff02::16"  ,"IPv6 MLDv2 reports"),
		("ff02::1:2" ,"IPv6 All DHCP servers and relay agents"),
		("ff02::1:3" ,"IPv6 All LLMNR hosts"),
		("ff05::1:3" ,"IPv6 All DHCP servers"),
		("ff02::c"   ,"IPv6 Simple Service Discovery (SSDP)"),
		("ff02::fb"  ,"IPv6 Multicast DNS"),
		("ff02::101" ,"IPv6 Network Time Protocol"),
		("ff02::108" ,"IPv6 Network Information Service"),
		("ff02::181" ,"IPv6 Precision Time (PTP v2 msgs)"),
		("ff02::6b"  ,"IPv6 Precision Time (PTP v2)"),
		("ff02::114" ,"Used for experiments")]
    return V6D

def NetScan():
   Hosts = [("192.168.255.255","Inner-192.168-Brd-Cast"),
		 ("255.255.255.255","Local Brd Cast"),
		 ("224.0.0.0","Base address (reserved)"),
		 ("224.0.0.252","All Routers multicast"),
		 ("224.0.0.254","Distance Vector Multicast Routing"),
		 ("224.0.0.1","All Hosts Multicast (On Same Network)"),
		 ("224.0.0.2","All Routers multicast (On Same Network)"),
		 ("224.0.0.4","Distance Vector Multicast Routing Protocol (DVMRP)"),
		 ("224.0.0.5","Open Shortest Path First Routing (OSPF)"),
		 ("224.0.0.6","All Designated Routers (OSPF)"),
		 ("224.0.0.9","Routing Information"),
		 ("224.0.0.10","Interior Gateway Routing (EIGRP)"),
		 ("224.0.0.13","Independent Multicast (PIM-V2)"),
		 ("224.0.0.18","Virtual Router Redundancy (VRRP)"),
		 ("224.0.0.19","IS-IS over IP (19)"),
		 ("224.0.0.20","IS-IS over IP (20)"),
		 ("224.0.0.21","IS-IS over IP (21)"),
		 ("224.0.0.22","Internet Group Management (IGMP-V3)"),
		 ("224.0.0.102","HSRPv2 and GLBP"), #(HSRPv2)=Hot Standby Router Protocol v2 and (GLBP)=Gateway Load Balancing Protocol
		 ("224.0.0.107","Precision Time Protocol (PTP-V2)"),
		 ("224.0.0.251","Multicast DNS (mDNS)"),
		 ("224.0.0.252","Link-local Multicast Name Resolution (LLMNR)"),
	   ("224.0.0.253","Teredo tunneling client discovery"),
		 ("224.0.1.1","Network Time Protocol listening"),
		 ("224.0.1.22","Service Location v1 (general)"),
		 ("224.0.1.35","Service Location v1 (directory agent)"),
		 ("224.0.1.39","CISCO AUTO-RP-ANNOUNCE (MultiCast)"),
		 ("224.0.1.40","CISCO AUTO-RP-DISCOVERY (MultiCast)"),
		 ("224.0.1.41","H.323 Gatekeeper discovery)"),
		 ("224.0.1.129","Precision Time (PTP v1&v2) 29"),
		 ("224.0.1.130","Precision Time (PTP v1) 30"),
		 ("224.0.1.131","Precision Time (PTP v1) 31"),
		 ("224.0.1.132","Precision Time (PTP v1) 32"),
		 ("239.255.255.250","Simple Service Discovery (SSDP)"),
		 ("239.255.255.253","Service Location v2")]
	LocIP = Scan('lo')
        msg = ('(\"'+str(LocIP)+'\" , \"[LocalHost Loop]\"'+')')
        a = (str(LocIP))
        b = (str("LocalHost"))
        c = ((a,b))
        Hosts.append(c)
	eth0 = 'enxb827eb00cead'
        HostIP  = Scan(str(eth0))
        nm = nmap.PortScanner()
        mac = nm.scan('192.168.1.0/24', arguments='-sP')
        for h in nm.all_hosts():
		#print "IP Found on the Network = " + str(h)
                if (nm[h]['addresses']['ipv4']) == str(HostIP):
			MACa = mac_for_ip(str(HostIP))
                        HostNames = (nm[h]['hostname'])
                        HostNames = HostNames.split(".home")
                        msg = ('(\"'+str(HostIP)+'\" , \"'+str(HostNames[0])+'\")')
                        #print msg
			a = (str(HostIP))
			MSG = ' IP Address Found on the Network= '+C.O+str(a)+C.W
			MSG += ' With Mac Address= '+C.P+str(MACa).lower()+C.W
                        b = (str(HostNames[0]))
			MSG += ' and HostName = '+C.T+str(b)+C.W
                        c = ((a,b))
                        Hosts.append(c)
			print MSG
                elif 'mac' in nm[h]['addresses']:
                        HostNames = (nm[h]['hostname'])
                        HostNames = HostNames.split(".home")
                        msg = ('(\"'+str(nm[h]['addresses']['ipv4'])+'\" , \"'+str(HostNames[0])+'\")')
			#print msg
                        a = (str(str(nm[h]['addresses']['ipv4'])))
			MSG = ' IP Address Found on the Network= '+C.O+str(a)+C.W
                        MSG += ' With Mac Address= '+C.P+(str(nm[h]['addresses']['mac'])).lower()+C.W
                        b = (str(HostNames[0]))
			MSG += ' and HostName = '+C.T+str(b)+C.W
                        c = ((a,b))
			print MSG
                        Hosts.append(c)
	return Hosts

def MacScan():
	Mac =[("ff:ff:ff:ff:ff:ff","Mac {Local Brd Cast}"),
              ("00:00:00:00:00:00","Mac {LocalHost}"),
              ("33:33:00:00:00:01","Mac {All-Nodes-MultiCast}"),
	      ("33:33:00:00:00:02","Mac {All-Routers-Multicast}"),
	      ("00:07:cb:03:9d:29","SlickR-Svr (Server VPN)"),
	      ("01:80:c2:00:00:0e","LLDP_Multicast")]
	eth0 = str('enxb827eb00cead')
	HostIP  = Scan(str(eth0))
        nm = nmap.PortScanner()
        mac = nm.scan('192.168.1.0/24', arguments='-sP')
        for h in nm.all_hosts():
		#print h
                if (nm[h]['addresses']['ipv4']) == str(HostIP):
			mac = mac_for_ip(str(HostIP))
                        HostNames = (nm[h]['hostname'])
                        HostNames = HostNames.split(".home")
                        msg = ('(\"'+str(mac)+'\" , \"'+str(HostNames[0])+'\")')
                        #print msg
                        a = (str(mac)).lower()
                        b = (str(HostNames[0]))
                        c = ((a,b))
                        Mac.append(c)
                elif 'mac' in nm[h]['addresses']:
                        HostNames = (nm[h]['hostname'])
                        HostNames = HostNames.split(".home")
                        msg = ('(\"'+str(nm[h]['addresses']['mac'])+'\" , \"'+str(HostNames[0])+'\")')
                        a = (str(nm[h]['addresses']['mac'])).lower()
			b = (str(HostNames[0]))
                        c = ((a,b))
                        Mac.append(c)
	return Mac

def mac_for_ip(ip):
    #Returns a list of MACs for interfaces that have given IP, returns None if not found
    for i in nif.interfaces():
        addrs = nif.ifaddresses(i)
        try:
            if_mac = addrs[nif.AF_LINK][0]['addr']
            if_ip = addrs[nif.AF_INET][0]['addr']
        except IndexError, KeyError: #ignore ifaces that dont have MAC or IP
            if_mac = if_ip = None
        if if_ip == ip:
            return if_mac
    return None
