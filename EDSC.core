#-*- coding: utf-8 -*-
#! usr/bin/python
from scapy.all import *
from ExMod import *
import MsgMod as MM
import SMod, DEF, os

def Setup():
	os.system('clear')
	MM.ScanMsgStart()

def Run(arg,arg2,Host,Mac,V6D,Num):
	pkt = sniff(count=1)[0]
	Eth = DEF.Ethers(pkt)
	Proto = DEF.Proto(pkt,Eth)
	Port = DEF.PortDef(pkt,Eth,Proto)
	if ((arg == "-t") or (arg2 == "-t")) or ((arg == "-d") or (arg2 == "-d")): Test(Num,pkt,Eth,Proto,Port)
	ProcStop = EXPT(Hosts,Mac,V6D,pkt,Eth,Proto,Port)
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
