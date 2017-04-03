#! usr/bin/python
#-*- coding: utf-8 -*-
from scapy.all import *
#import Color as C
import itertools, threading, socket, fcntl, struct, nmap, os, sys, time

W  = '\033[0m'  # white (normal)
R  = '\033[31m' # red
G  = '\033[32m' # green
O  = '\033[33m' # orange
B  = '\033[34m' # blue
P  = '\033[35m' # purple
C  = '\033[36m' # cyan
GR = '\033[37m' # gray
T  = '\033[93m' # tan

def DnsInfo(pkt,Hosts,Eth,Mac,V6):
	ipa = ipaCheck(pkt,Hosts,Eth,Mac)
	msg = DnsCheck(pkt,Hosts,Eth,Mac,V6,ipa)
	#print msg
	return msg

def DnsCheck(pkt,Hosts,Eth,Mac,V6,ipa):
	if len(ipa) ==  2:
		if "Error" in ipa:
	                Dns1 = ipa[0]
        	        Dns2 = ipa[1]
                	msg = 'Dns src: ['+R+Dns1+W+']  Dns dst: ['+R+Dns2+W+'] '
                	#print msg
                	return msg
		else:
			uipa = ipa[0]
			Dns1 = RevDNS1(pkt,Hosts,Eth,Mac,V6,uipa)
			uipa = ipa[1]
			Dns2 = RevDNS2(pkt,Hosts,Eth,Mac,V6,uipa)
              		msg = 'Dns src: ['+T+Dns1+W+']  Dns dst: ['+T+Dns2+W+'] '
                	#print msg
			return msg
        else:
		uipa = ipa
		Dns2 = RevDNS2(pkt,Hosts,Eth,Mac,V6,uipa)
                Dns1 = RevDNS1(pkt,Hosts,Eth,Mac,V6,uipa)
                msg = 'Dns src: ['+T+Dns1+W+']  Dns dst: ['+T+Dns2+W+'] '
                #print msg
		return msg

def ipaCheck(pkt,Hosts,Eth,Mac):
	ipas = []
	hd = dict(Hosts)
	md = dict(Mac)
	#print 'Eth : '+str(Eth)
	if Eth == "IPv4":
		Eth="IP"
		#print 'Eth : '+str(Eth)
		ipas = info(pkt,Hosts,Eth,hd,md,ipas)
		return ipas
	elif Eth == "IPv6":
		#print 'Eth : '+str(Eth)
		ipas = info(pkt,Hosts,Eth,hd,md,ipas)
                return ipas
	else:
		try:
	        	#print 'Except Eth : '+str(Eth)
			#print 'src: '+str(pkt[Ether].src)+' dst: '+str(pkt[Ether].dst)
			if str(pkt[Ether].src) or str(pkt[Ether].dst) in md.keys():
				if str(pkt[Eth].src) not in md.keys():
                        		ipd = md.get(str(pkt[Ether].dst))
                        		#print iph
                        		ips = str(pkt[Ether].src)
                        		#print ipa
                        		ipas.append(ips)
                        		ipas.append(ipd)
                        		return ipas
                		elif str(pkt[Eth].dst) not in md.keys():
                        		ips = md.get(str(pkt[Ether].src))
                        		#print iph
                        		ipd = str(pkt[Ether].dst)
                        		#print ipa
                        		ipas.append(ips)
                        		ipas.append(ipd)
                        		return ipas
                		else:
					ips = md.get(str(pkt[Ether].src))
					ipd = md.get(str(pkt[Ether].dst))
                        		ipas.append(ips)
                        		ipas.append(ipd)
        	        		return ipas
			else:
				#print 'Try Eth : '+str(Eth)
                        	#print 'src: '+str(pkt[Eth].src)+' dst: '+str(pkt[Eth].dst)
                        	ipas.append(str(pkt[Eth].src))
                        	ipas.append(str(pkt[Eth].dst))
                        	return ipas
		except:
			#print 'Exc Eth : '+str(Ether)
                        #print 'src: '+str(pkt[Ether].src)+' dst: '+str(pkt[Ether].dst)
                        #ipas.append(str(pkt[Ether].src))
                        #ipas.append(str(pkt[Ether].dst))
			ipas.append(str("Error DNS Src"))
			ipas.append(str("Error DNS dst"))
                        return ipas

def info(pkt,Hosts,Eth,hd,md,ipas):
	if str(pkt[Eth].src) or str(pkt[Eth].dst) in hd.keys():
       		if str(pkt[Eth].src) not in hd.keys():
			iph = hd.get(str(pkt[Eth].dst))
                	#print iph
                       	ipa = str(pkt[Eth].src)
			#print ipa
			ipas.append(ipa)
			ipas.append(iph)
            		return ipas
		elif str(pkt[Eth].dst) not in hd.keys():
                     	iph = hd.get(str(pkt[Eth].src))
                      	#print iph
                      	ipa = str(pkt[Eth].dst)
                      	#print ipa
			ipas.append(iph)
                        ipas.append(ipa)
                        return ipas
		else:
			#print 'src: '+str(pkt[Eth].src)+' dst: '+str(pkt[Eth].dst)
			ipas.append(str(pkt[Eth].src))
			ipas.append(str(pkt[Eth].dst))
			return ipas
	else:
		#print 'src: '+str(pkt[Eth].src)+' dst: '+str(pkt[Eth].dst)
                ipas.append(str(pkt[Eth].src))
                ipas.append(str(pkt[Eth].dst))
                return ipas

def RevDNS1(pkt,Hosts,Eth,Mac,V6,uipa):
	HD = dict(Hosts)
	MD = dict(Mac)
	try:
		name, alias, addresslist = socket.gethostbyaddr(uipa)
		#print '***** Rev DNS 1 Info (try) *****'
		#print uipa
		#print 'name: '+str(name)
		#print 'alias: '+str(alias)
		#print 'address'+str(addresslist)
	    	if ".home" in name:
			dns = str(name).split(".home")
			#print 'if ".home" in dns= '+str(dns[0])
			return dns[0]
	    	else:
			dns = str(name)
			if dns in HD.values():
                        	#print 'RevDNS1 --> if HD.Values = '+str(dns)
                        	return dns
                	else:
				#print 'RevDNS1 --> else = '+str(name)
                        	#print str(name)
                        	return name
	except:
		#print '***** Rev DNS 1 Info (except) *****'
                #print uipa
		if Eth == "IPv4":
                        if uipa in HD.keys():
                                DNS = HD.get(uipa)
                                msg = T+str(DNS)+W
				#print 'IPv4 HD.Keys() DNS ='+str(DNS)
                                #print msg
                                return msg
			elif uipa in HD.values():
				DNS= uipa
				msg = T+str(DNS)+W
				#print 'IPv4 HD.Values() DNS ='+str(DNS)
                                #print msg
                                return msg
                        else:
				#print 'IPv4 No DNS'
                                msg = R+' No DNS '+W+' For:'+T+str(uipa)+W
				#print msg
                                return msg
                elif Eth == "IPv6":
                        if uipa in V6.keys():
                                DNS = V6.get(uipa)
                                msg = T+str(DNS)+W
				#print 'IPv6 V6.Keys() DNS ='+str(DNS)
                                #print msg
                                return msg
			elif uipa in V6.values():
                                DNS= uipa
                                msg = T+str(DNS)+W
				#print 'IPv6 V6.Values() DNS ='+str(DNS)
                                #print msg
                                return msg
                        else:
				#print 'IPv6 No DNS'
                                msg = R+' No DNS '+W+' For:'+T+str(uipa)+W
				#print msg
                                return msg
                else:
                        if uipa in MD.keys():
                                DNS = MD.get(uipa)
                                msg = T+str(DNS)+W
				#print 'Mac MD.Keys() DNS ='+str(DNS)
                                #print msg
                                return msg
			elif uipa in MD.values():
                                DNS= uipa
                                msg = T+str(DNS)+W
				#print 'Mac MD.Values() DNS ='+str(DNS)
                                #print msg
                                return msg
                        else:
				#print 'Mac No DNS'
                                msg = R+' No DNS '+W+' For:'+T+str(uipa)+W
				#print msg
                                return msg

def RevDNS2(pkt,Hosts,Eth,Mac,V6,uipa):
	HD = dict(Hosts)
	MD = dict(Mac)
        try:
                name, alias, addresslist = socket.gethostbyaddr(uipa)
		#print '***** Rev DNS 2 Info (try) *****'
		#print uipa
		#print 'name: '+str(name)
                #print 'alias: '+str(alias)
                #print 'address'+str(addresslist)
		if ".home" in name:
                        dns = str(name).split(".home")
                        #print 'if ".home" in dns= '+str(dns[0])
                        return dns[0]
                else:
                        dns = str(name)
                        if dns in HD.values():
                                #print 'RevDNS2 --> if HD.Values = '+str(dns)
                                return dns
                        else:
                                #print 'RevDNS2 --> else = '+str(name)
                                #print str(name)
                                return name
        except:
		#print '***** Rev DNS 2 Info (except) *****'
                #print uipa
		if Eth == "IPv4":
			if uipa in HD.keys():
                                DNS = HD.get(uipa)
                                msg = T+str(DNS)+W
				#print 'IPv4 HD.Keys() DNS ='+str(DNS)
				#print msg
                                return msg
			elif uipa in HD.values():
                                DNS= uipa
                                msg = T+str(DNS)+W
				#print 'IPv4 HD.Values() DNS ='+str(DNS)
				#print msg
                                return msg
                        else:
				#print "IPv4 No DNS"
                                msg = R+' No DNS '+W+' For:'+T+str(uipa)+W
				#print msg
                                return msg
		elif Eth == "IPv6":
			if uipa in V6.keys():
				DNS = V6.get(uipa)
				#print 'IPv6 V6.Keys() DNS ='+str(DNS)
				msg = T+str(DNS)+W
				#print msg
                		return msg
			elif uipa in V6.values():
                                DNS= uipa
                                msg = T+str(DNS)+W
				#print 'IPv6 V6.Values() DNS ='+str(DNS)
				#print msg
                                return msg
			else:
				#print "IPv6 No DNS"
				msg = R+' No DNS '+W+' For:'+T+str(uipa)+W
				#print msg
				return msg
		else:
			if uipa in MD.keys():
                                DNS = MD.get(uipa)
				#print 'Mac MD.Keys() DNS ='+str(DNS)
                                msg = T+str(DNS)+W
				#print msg
				return msg
			elif uipa in MD.values():
                                DNS= uipa
                                msg = T+str(DNS)+W
				#print 'Mac MD.Values() DNS ='+str(DNS)
				#print msg
                                return msg
                        else:
				#print "Mac No DNS"
                                msg = R+' No DNS '+W+' For:'+T+str(uipa)+W
				#print msg
                                return msg
