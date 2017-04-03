#! usr/bin/python
#-*- coding: utf-8 -*-
from scapy.all import *
from DNSMod import DnsInfo as DI
#import Color as C
import sys, os

W  = '\033[0m'  # white (normal)
R  = '\033[31m' # red
G  = '\033[32m' # green
O  = '\033[33m' # orange
B  = '\033[34m' # blue
P  = '\033[35m' # purple
C  = '\033[36m' # cyan
GR = '\033[37m' # gray
T  = '\033[93m' # tan

def MsgStart():
	print '\n\n\t\t\t************  Starting Network Sniffer  ************\n'

def MsgStop():
        print '\n\n\t\t\t************ User Stoped Network Sniffer ************\n'

def ScanMsgStart():
	print '\n\n\t\t\t************ Starting Scan on Network for IPs ************\n'

def ScanMsgStop():
	print '\n\n\t\t\t******************** Network Scan Done *******************\n'

def DicoMsg(Hosts,Mac,V6D):
	print '\n***** Building The Dictionaries *****\n'
	print '\n***** '+C+'Adding Mac Dict'+W+' *****\n'
        print Mac
	print '\n***** '+C+'Adding V4  Dict'+W+' *****\n'
        print Hosts
	print '\n***** '+C+'Adding V6  Dico'+W+' *****\n'
        print V6D
        print '\n***** All Dictionaries Done *****\n'

def ErrorMsg(Num,pkt,Eth,proto,Port):
	msg = '\n['+R+str(Num)+W+'\t] ['+R+'Packet Error: '+W+' Ether= '+O+str(Eth)+W+'Proto= '+G+str(Proto)+W+' Port= '+P+str(Port)+'] '+W
	msg +='\n    '+C+pkt.summary()+W
        print msg

def InnerMsg(Num,pkt):
	msg = '\n['+R+str(Num)+W+'\t] [******* '+G+'Inter Network Traffic'+W+' ********] '+C+pkt.summary()+W
        print msg

def fordebugmsg(Num,pkt,Eth,Proto,Port):
	msg = '['+R+str(Num)+W+'\t] [ Ether='+O+str(Eth)+W+' Proto='+G+str(Proto)+W+' Port='+P+str(Port)+W+'] Packet = '+C+pkt.summary()+W
	print msg

def MainInfo(arg,arg2,Hosts,Mac,V6D,Num,pkt,Eth,Proto,Port,ProcStop):
        V6 = dict(V6D)
	HD = dict(Hosts)
	MD = dict(Mac)
        if ((arg == "-s") or (arg2 == "-s")):
                if ProcStop != "1":
			if ProcStop == "3":
                        	if (Eth == "IPv4" or Eth == "IPv6") and Proto == "UDP":
                                	MsWarningMsg(Hosts,Mac,V6,Num,pkt,Eth,Proto,Port,HD,MD)
                        	elif Eth == "ARP":
                                	ARPinnerMsg(Num,pkt,Eth,Proto)
                        	else:
                                	msg = '\n['+R+str(Num)+W+'\t] [ '+R+'Other (ProcStop == 3)'+W+' ] not yet defined for = '+C+pkt.summary()+W
                                	print msg
                                	pass
			elif ProcStop == "4": WarningMsg(Num,pkt,Eth,Proto,Port)
			else:
                        	msg = '\n['+R+str(Num)+W+'\t] [ Traffic ' +O+ Eth +W+ ' Proto= '+G+ Proto +W+ ' Port= ' +P+ Port +W+ ' ] '
                        	msg +='\n    '+DI(pkt,Hosts,Eth,Mac,V6)
				msg +='\n\t'+C+pkt.summary()+W
                		print msg
		else: pass
        if ((arg == "-f") or (arg2 == "-f")):
                if ProcStop != "1":
                        if ProcStop == "3":
                                if (Eth == "IPv4" or Eth == "IPv6") and Proto == "UDP":
                                        MsWarningMsg(Hosts,Mac,V6,Num,pkt,Eth,Proto,Port,HD,MD)
					msg += '\n\t[ Additional Data Coming Soon ]'
                        		msg += '\n\t   '+C+pkt.summary()+W
                        		print msg
                                elif Eth == "ARP":
                                        ARPinnerMsg(Num,pkt,Eth,Proto)
					msg += '\n\t[ Additional Data Coming Soon ]'
                        		msg += '\n\t   '+C+pkt.summary()+W
                        		print msg
                                else:
                                        msg = '\n['+R+str(Num)+W+'\t] [ '+R+'Other (ProcStop == 3)'+W+' ] not yet defined'
                                        msg += '\n\t[ Additional Data Coming Soon ]'
                        		msg += '\n\t   '+C+pkt.summary()+W
                        		print msg
                                        pass
			elif ProcStop == "4": WarningMsg(Num,pkt,Eth,Proto,Port)
                        else:
                                msg = '\n['+R+str(Num)+W+'\t] [ Traffic ' +O+ Eth +W+ ' Proto= '+G+ Proto +W+ ' Port= ' +P+ Port +W+ ' ] '
                                msg +='\n    '+DI(pkt,Hosts,Eth,Mac,V6)
                                msg += '\n\t[ Additional Data Coming Soon ]'
                        	msg += '\n\t   '+C+pkt.summary()+W
                        	print msg
            	else: pass
        if ((arg == "-h") or (arg2 == "-h")):
		print '\n'
                print " This is the Help File: blablablabla "
        if ((arg == "-a") or (arg2 == "-a")):
		if ProcStop != "1":
                        if ProcStop == "3":
                                if (Eth == "IPv4" or Eth == "IPv6") and Proto == "UDP":
                                        msg = '\n['+R+str(Num)+W+'\t] '+C+pkt.summary()+W
					MsWarningMsg(Hosts,Mac,V6,Num,pkt,Eth,Proto,Port,HD,MD)
                                elif Eth == "ARP":
					msg = '\n['+R+str(Num)+W+'\t] '+C+pkt.summary()+W
                                        ARPinnerMsg(Num,pkt,Eth,Proto)
                                else:
                                        msg = '\n['+R+str(Num)+W+'\t] [ '+R+'Other (ProcStop == 3)'+W+' ] not yet defined for = '+C+pkt.summary()+W
                                        print msg
                                        pass
			elif ProcStop == "4": WarningMsg(Num,pkt,Eth,Proto,Port)
                        else:
                                msg = '\n['+R+str(Num)+W+'\t] '+C+pkt.summary()+W
                                print msg
                else: pass
	if ((arg == "-A") or (arg2 == "-A")):
		if ProcStop != "1":
                      	msg = '\n['+R+str(Num)+W+'\t] '+C+pkt.summary()+W
                	print msg
                	print pkt.show()
                else: pass
	if ((arg == "-n") or (arg2 == "-n")):
		if ProcStop != "4": pass
		else: WarningMsg(Num,pkt,Eth,Proto,Port)
        if ((arg == "-g") or (arg2 == "-g")):
		if ProcStop == "4": WarningMsg(Num,pkt,Eth,Proto,Port)
		else:
	        	msg ='\n['+R+str(Num)+W+'\t] ['+O+' Info not yet definded '+W+'] '+C+pkt.summary()+W
              		print msg
		  	pass
        else: pass

def WarningMsg(Num,pkt,Eth,Proto,Port):
	msg =R+'\n[------------------------------------------------------------------------'
	msg += '\n[********** Warning **********\t'+W+'['+R+str(Num)+W+'\t]'+R+'  ********** Warning ***********'
	msg += '\n['
	msg += '\n['+W+' [ Traffic '+O+str(Eth)+W+' Proto= '+G+str(Proto)+W+' Port= '+P+str(Port)+W+') ]'+R
	msg += '\n[\t'+C+pkt.summary()+R
	msg += '\n['
	msg += '\n[********** Warning **********\t Warning   ********** Warning ***********'
	msg += '\n[------------------------------------------------------------------------'+W
        print msg

def ARPinnerMsg(Num,pkt,Eth,Proto):
	msg = '\n['+R+str(Num)+W+'\t] [ Traffic '+O+Eth+W+' OP= '+G+Proto+W+' Info= '+P+'Internal ARP Query'+W+') ] '+C+pkt.summary()+W
        print msg

def MsWarningMsg(Hosts,Mac,V6,Num,pkt,Eth,Proto,Port,HD,MD):
	msg = '\n[*****'+R+' Microsoft Traffic '+W+'*****] '
        msg +='\n['+R+str(Num)+W+'\t] [ Traffic ' +O+ Eth +W+ ' (' +G+ Proto +W+ ' ' +P+ Port +W+ ') ] '
        msg +='\n    '+DI(pkt,Hosts,Eth,Mac,V6)
	msg +='\n\t'+C+pkt.summary()+W
        print msg
