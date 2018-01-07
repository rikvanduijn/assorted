#!/usr/bin/python


from os import geteuid, devnull
import logging
from scapy.all import *
from sys import exit
import argparse
from collections import OrderedDict
from subprocess import Popen, PIPE
import random
import md5
import hashlib

logging.basicConfig(filename='credentials.txt',level=logging.INFO)
DN = open(devnull, 'w')

#Console colors
W = '\033[0m'  # white (normal)
T = '\033[93m'  # tan

honeyip = ['\033[106m', '\033[96m']
attackers = {'185.103.243.208': honeyip}

class bcolors:
	HEADER = '\033[95m'
 	OKBLUE = '\033[94m'
 	OKGREEN = '\033[92m'
 	WARNING = '\033[93m'
 	FAIL = '\033[91m'
 	ENDC = '\033[0m'
 	BOLD = '\033[1m'
 	UNDERLINE = '\033[4m'

def getColor(ip, msg):
	ips = [41,42,43,44,45,46,47,100,101,102,103,104,105,106,107]
	messages = [31,32,33,34,35,36,37,90,91,92,93,94,95,96,97]
	text = ""
	pref = "==> "
	if(ip == "185.103.243.208"):
		pref = "<== "
	if ip in attackers:
		newip = hashlib.md5(ip).hexdigest()
		ipcolor =  attackers[ip][0]
		msgcolor = attackers[ip][1]
		text = pref + ipcolor + str(newip.ljust(15)) + bcolors.ENDC + msgcolor + " " + msg + bcolors.ENDC
		return text
	else:
		newip = hashlib.md5(ip).hexdigest()
		ipcolor = '\033[' +str(random.choice(ips)) + 'm'
		msgcolor = '\033[' +  str(random.choice(messages)) + 'm'
		attackers[ip] = [ipcolor, msgcolor]
		text = pref + ipcolor + str(newip.ljust(15)) + bcolors.ENDC + msgcolor + " " + msg + bcolors.ENDC
                return text 

pkt_frag_loads = OrderedDict()
telnet_stream = OrderedDict()

def parse_args():
   """Create the arguments"""
   parser = argparse.ArgumentParser()
   parser.add_argument("-i", "--interface", help="Choose an interface")
   parser.add_argument("-p", "--pcap", help="Parse info from a pcap file; -p <pcapfilename>")
   parser.add_argument("-f", "--filterip", help="Do not sniff packets from this IP address; -f 192.168.0.4")
   parser.add_argument("-v", "--verbose", help="Display entire URLs and POST loads rather than truncating at 100 characters", action="store_true")
   return parser.parse_args()


def iface_finder():
	try:
		ipr = Popen(['/sbin/ip', 'route'], stdout=PIPE, stderr=DN)
		for line in ipr.communicate()[0].splitlines():
			if 'default' in line:
				l = line.split()
				iface = l[4]
				return iface
	except IOError:
		exit('[-] Could not find an internet active interface; please specify one with -i <interface>')


def frag_remover(ack, load):
	'''
	Keep the FILO OrderedDict of frag loads from getting too large
	3 points of limit:
		Number of ip_ports < 50
		Number of acks per ip:port < 25
		Number of chars in load < 5000
	'''
	global pkt_frag_loads

	# Keep the number of IP:port mappings below 50
	# last=False pops the oldest item rather than the latest
	while len(pkt_frag_loads) > 50:
		pkt_frag_loads.popitem(last=False)

	# Loop through a deep copy dict but modify the original dict
	copy_pkt_frag_loads = copy.deepcopy(pkt_frag_loads)
	for ip_port in copy_pkt_frag_loads:
		if len(copy_pkt_frag_loads[ip_port]) > 0:
			# Keep 25 ack:load's per ip:port
			while len(copy_pkt_frag_loads[ip_port]) > 25:
				pkt_frag_loads[ip_port].popitem(last=False)

	# Recopy the new dict to prevent KeyErrors for modifying dict in loop
	copy_pkt_frag_loads = copy.deepcopy(pkt_frag_loads)
	for ip_port in copy_pkt_frag_loads:
		# Keep the load less than 75,000 chars
		for ack in copy_pkt_frag_loads[ip_port]:
			# If load > 5000 chars, just keep the last 200 chars
			if len(copy_pkt_frag_loads[ip_port][ack]) > 5000:
				pkt_frag_loads[ip_port][ack] = pkt_frag_loads[ip_port][ack][-200:]

def frag_joiner(ack, src_ip_port, load):
	'''
	Keep a store of previous fragments in an OrderedDict named pkt_frag_loads
	'''
	for ip_port in pkt_frag_loads:
		if src_ip_port == ip_port:
			if ack in pkt_frag_loads[src_ip_port]:
				# Make pkt_frag_loads[src_ip_port][ack] = full load
				old_load = pkt_frag_loads[src_ip_port][ack]
				concat_load = old_load + load
				return OrderedDict([(ack, concat_load)])

	return OrderedDict([(ack, load)])

pktBundle = {}
def pkt_parser(pkt):
	if pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP):
		if pkt[TCP].dport == 23 or pkt[TCP].sport ==23:
			#print pkt.show()
			load = pkt[Raw].load
			ack = str(pkt[TCP].ack)
			seq = str(pkt[TCP].seq)
			src_ip_port = str(pkt[IP].src) + ':' + str(pkt[TCP].sport)
			dst_ip_port = str(pkt[IP].dst) + ':' + str(pkt[TCP].dport)
			frag_remover(ack, load)
			frags = frag_joiner(ack, src_ip_port, load)

			sig = src_ip_port + "-" + dst_ip_port
			if(not sig in pktBundle):
				pktBundle[sig] = ""
			
			for f in frags:
				pktBundle[sig] = pktBundle[sig] + frags[f]
 			
			currentStr = pktBundle[sig]
			if("\x0d" in currentStr or "\x0a" in currentStr):
				if(len(currentStr) > 2):
					print(getColor(str(pkt[IP].src),currentStr))
				pktBundle[sig] = ""
			
			#full_load = pkt_frag_loads[src_ip_port][ack]
			#import  binascii;

			#if("\x0d" in full_load):
			#print(getColor(str(pkt[IP].src), full_load))
			#printer(src_ip_port, dst_ip_port, full_load)
			#printer(src_ip_port, dst_ip_port, pkt[Raw].load)
#			telnet_logins(src_ip_port, dst_ip_port, load, ack, seq)



def telnet_logins(src_ip_port, dst_ip_port, load, ack, seq):
	'''
	Catch telnet logins and passwords
	'''
	global telnet_stream

	msg = None
	if src_ip_port in telnet_stream:
		# Do a utf decode in case the client sends telnet options before their username
		# No one would care to see that
		try:
			telnet_stream[src_ip_port] += load.decode('utf8')
		except UnicodeDecodeError:
			pass

		# \r or \r\n or \n terminate commands in telnet if my pcaps are to be believed
		if '\r' in telnet_stream[src_ip_port] or '\n' in telnet_stream[src_ip_port]:
			telnet_split = telnet_stream[src_ip_port].split(' ', 1)
			cred_type = telnet_split[0]
			value = telnet_split[1].replace('\r\n', '').replace('\r', '').replace('\n', '')
			# Create msg, the return variable
			msg = 'Telnet %s: %s' % (cred_type, value)
			printer(src_ip_port, dst_ip_port, msg)
			del telnet_stream[src_ip_port]

	# This part relies on the telnet packet ending in
	# "login:", "password:", or "username:" and being <750 chars
	# Haven't seen any false+ but this is pretty general
	# might catch some eventually
	# maybe use dissector.py telnet lib?
	if len(telnet_stream) > 100:
		telnet_stream.popitem(last=False)
	mod_load = load.lower().strip()
	printer(src_ip_port, dst_ip_port, mod_load)
	if mod_load.endswith('username:') or mod_load.endswith('login:'):
		telnet_stream[dst_ip_port] = 'username '
	elif mod_load.endswith('password:'):
		telnet_stream[dst_ip_port] = 'password '

def printer(src_ip_port, dst_ip_port, msg):
	if dst_ip_port != None:
		if "185.103.243.208" in src_ip_port:
			print bcolors.WARNING + msg +bcolors.ENDC
		else:
			print bcolors.OKGREEN + msg +bcolors.ENDC

def main(args):
	##################### DEBUG ##########################
	## Hit Ctrl-C while program is running and you can see
	## whatever variable you want within the IPython cli
	## Don't forget to uncomment IPython in imports
	#def signal_handler(signal, frame):
	#	embed()
	##	sniff(iface=conf.iface, prn=pkt_parser, store=0)
	#	sys.exit()
	#signal.signal(signal.SIGINT, signal_handler)
	######################################################

	# Read packets from either pcap or interface
	if args.pcap:
		try:
			for pkt in PcapReader(args.pcap):
				pkt_parser(pkt)
		except IOError:
			exit('[-] Could not open %s' % args.pcap)

	else:
		# Check for root
		if geteuid():
			exit('[-] Please run as root')

		#Find the active interface
		if args.interface:
			conf.iface = args.interface
		else:
			conf.iface = iface_finder()
		print '[*] Using interface:', conf.iface

		if args.filterip:
			sniff(iface=conf.iface, prn=pkt_parser, filter="not host %s" % args.filterip, store=0)
		else:
			sniff(iface=conf.iface, prn=pkt_parser, store=0)


if __name__ == "__main__":
   main(parse_args())


