#! usr/bin/python
#-*- coding: utf-8 -*-
from scapy.all import *
import DNSMod
from MsgMod import fordebugmsg as FDM

def Test(Num,pkt,Eth,Proto,Port):
        if Eth == "IPv4":
                if Proto == "TCP":
                        if Port == "Putty": pass #InnerMsg(pkt)
                        else: FDM(Num,pkt,Eth,Proto,Port)
                else: FDM(Num,pkt,Eth,Proto,Port)
        else: FDM(Num,pkt,Eth,Proto,Port)

def EXPT(Hosts,Mac,V6D,pkt,Eth,Proto,Port):
        HD = dict(Hosts)
        MD = dict(Mac)
        V6 = dict(V6D)
        if Eth == "IPv4":
                ProcStop = IPv4Ex(HD,MD,pkt,Eth,Proto,Port)
                return ProcStop
        elif Eth == "IPv6":
                ProcStop = IPv6Ex(HD,MD,V6,pkt,Eth,Proto,Port)
                return ProcStop
        elif Eth == "ARP":
                ProcStop = ARPEX(MD,pkt,Eth,Proto)
                return ProcStop
                pass
	elif Eth == "HomePlug MME":
		ProcStop = HomePlug(MD,pkt,Eth,Proto)
		return ProcStop
        else:
                Proto = "Unknown"
                return Proto

def IPv4Ex(HD,MD,pkt,Eth,Proto,Port):
	Eth = "IP"
        if str(pkt[Eth].src) in HD.keys() and str(pkt[Eth].dst) in HD.keys():
            	ProcStop = "1"
            	return ProcStop
        if Proto == "TCP":
        	if Port == "Putty":
                	ProcStop = "1"
                        return ProcStop
                elif str("Pop-Corn") in Port:
                        ProcStop = "1"
                        return ProcStop
               	else:
			ProcStop = "2"
			return ProcStop
       	elif Proto == "IGMP":
        	ProcStop = "1"
                return ProcStop
     	elif Proto == "UDP":
        	if str("Microsoft") in str(pkt[Proto].payload):
                	ProcStop = "3"
                        return ProcStop
               	elif str("Pop-Corn") in Port:
                       	ProcStop = "1"
                	return ProcStop
        	else:
			ProcStop = "2"
                        return ProcStop
        else:
		ProcStop = "2"
		return ProcStop

def IPv6Ex(HD,MD,V6,pkt,Eth,Proto,Port):
	if str(pkt[Eth].src) in V6.keys() and str(pkt[Eth].dst) in V6.keys():
        	ProcStop = "1"
                return ProcStop
   	if Proto == "IPv6-ICMP":
                ProcStop = "1"
                return ProcStop
      	elif Proto == "UDP":
        	if str("Microsoft") in str(pkt[Eth].payload):
                	ProcStop = "3"
                        return ProcStop
              	else:
			ProcStop = "2"
                	return ProcStop
    	else:
		ProcStop = "2"
                return ProcStop

def ARPEX(MD,pkt,Eth,Proto):
	if (str(pkt[Eth].hwsrc) in MD.keys()) and (str(pkt[Eth].hwdst) in MD.keys()):
		ProcStop = "1"
        	pass
        	return ProcStop
	elif (str(pkt[Eth].hwsrc) not in MD.keys()) or (str(pkt[Eth].hwdst) not in MD.keys()):
                ProcStop = "4"
                pass
                return ProcStop
	else:
		ProcStop = "4"
		pass
		return ProcStop

def HomePlug(MD,pkt,Eth,Proto):
	if (str(pkt[Ether].src) in MD.keys()) and (str(pkt[Ether].dst) in MD.keys()):
                ProcStop = "1"
                pass
                return ProcStop
        else:
                ProcStop = "4"
                pass
                return ProcStop
