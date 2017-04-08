#! usr/bin/python
#-*- coding: utf-8 -*-
from scapy.all import *
from ExMod import *
import MsgMod as MM
import SMod, DEF, os

W  = '\033[0m'  # white (normal)
R  = '\033[31m' # red

def Setup():
	os.system('clear')
	MM.ScanMsgStart()

def Run(arg,arg2,Host,Mac,V6D,Num):
	DicEth=("HomePlug AV MME","MS-LLDP", "ARP","HomePlug MME")
	pkt = sniff(count=1)[0]
	Eth = DEF.Ethers(pkt)
	Proto = DEF.Proto(pkt,Eth)
	Port = DEF.PortDef(pkt,Eth,Proto)
	if ((arg == "-t") or (arg2 == "-t")) or ((arg == "-d") or (arg2 == "-d")): Test(Num,pkt,Eth,Proto,Port)
	ProcStop = EXPT(Hosts,Mac,V6D,pkt,Eth,Proto,Port)
	msg = "\n========================================"
	msg += "\narg= "+R+str(arg)+W+" arg2= "+R+str(arg2)+W #+" Host= "+R+str(Hosts)+W+" MacAdd= "+R+str(Mac)+W+"IPv6"+R+str(V6D)+W
	msg += "\nTram Number= "+R+str(Num)+W+" Eth= "+R+str(Eth)+W+" Protocol= "+R+str(Proto)+W+" Port= "+R+str(Port)+W
        msg += "\nRaw Packet= "+R+str(pkt)+W
	if (str(Port) == str("Putty")) or (str(Eth) in DicEth) or (str(Proto)==str("IGMP")): pass
	else: print msg
	MM.MainInfo(arg,arg2,Hosts,Mac,V6D,Num,pkt,Eth,Proto,Port,ProcStop)

def Stop():
        MM.MsgStop()

if __name__ == '__main__':
	Setup()
	arg, arg2 = DEF.ArgDef1(), DEF.ArgDef2()
	Hosts, Mac, V6D = SMod.NetScan(), SMod.MacScan(), SMod.V6DScan()
	MM.ScanMsgStop()
	if ((arg == "-d") or (arg2 == "-d")): MM.DicoMsg(Hosts,Mac,V6D)
	N = 0
    	MM.MsgStart()
	try:
		while True:
			if N == 1000000: N = 0
			Num = str(N).zfill(6)
			Run(arg,arg2,Hosts,Mac,V6D,Num)
			N += 1
	except KeyboardInterrupt:
                Stop()
