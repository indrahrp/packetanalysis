from datetime import datetime,date,timedelta
import re,copy
import itertools

#packetlist=[]		
###packetlist1=[]
###packetlist2=[]
###capture=[]
###capturelist=[]
###captarray1=[]
###captarray2=[]
###tcpipsession=[]

class Packet(object):
	def __init__(self,timestamp,iplength1,tos,id,offset,iplength2,sourceip,sourceport,destip,destport,prot,iplength3):
		self.timestamp=timestamp
		self.iplength1=iplength1
		self.id=id
		self.offset=offset
		self.iplength2=iplength2
		self.sourceip=sourceip
		self.sourceport=sourceport
		self.destip=destip
		self.destport=destport
		self.ipength3=iplength3
	
	def getpacketid(self):
		return (self.id)
	
	def __str__(self):
		return (self.timestamp + " id " + str(self.id)+ " sip " + self.sourceip + " sport "+self.sourceport + " dip " \
		+ self.destip + " dport " + self.destport + " lght " + self.iplength1)
	
	def uniquenes(self):
		#return (self.timestamp + " " + self.sourceip +'.' +  self.sourceport + " " + self.destip + "." +self.destport + " " + self.id + " " + self.iplength1)
		return ( self.sourceip +'.' +  self.sourceport + " " + self.destip + "." +self.destport + " " + self.id + " " + self.iplength1)

	def spec_session(self):
		#return (self.timestamp + " " + self.sourceip +'.' +  self.sourceport + " " + self.destip + "." +self.destport + " " + self.id + " " + self.iplength1)
		return ( self.sourceip +'.' +  self.sourceport + " " + self.destip + "." +self.destport)
	
	def spec_source_destip(self):
		return ( self.sourceip +' '+ self.destip)
	
		
	
	def tcpipsession(self):
		return ( self.sourceip +'.' +  self.sourceport + " " + self.destip + "." +self.destport)
	
	def __cmp__(self,otherpacketcapt):
		if otherpacketcapt.timestamp == self.timestamp and \
		   otherpacketcapt.sourceip == self.sourceip and  \
		   otherpacketcapt.sourceport == self.sourceport and  \
		   otherpacketcapt.destip == self. destip and \
		   otherpacketcapt.destport == self.destport  and \
		   otherpacketcapt.id==self.id:
				print "(in _cmp_)"
				return 1
		else:
			return  0

		##Packet(timestamp,iplength1,tos,id,offset,iplength2,sourceip,sourceport,destip,destport,prot,iplength3)
	


def loadToObject(filename,captarray):
		# the source of packet capture :
		# tcpdump -tttt -v  -nnner ticker.p3p1.13.out
		"""2016-10-30 00:00:04.631537 00:1b:21:d9:43:3c > 01:00:5e:28:d9:41, ethertype IPv4 (0x0800), length 319: (tos 0xec, ttl 32, id 38432, offset 0, flags [none], proto UDP (17), length 305)
		162.8.201.1.41802 > 233.40.217.65.10305: UDP, length 277"""
		#global capturelist
		capturelist=[]
		f=open(filename,'r')
		i=0
		cnt=0
		for lineitem in f:
			#print "line item cnt " + str(cnt) + " " + lineitem
			cnt=cnt + 1
			wrongpacket=0
			if cnt % 2 == 1:
				if lineitem.startswith('2016'):
					entries1=lineitem.split(",")
					#print entries1
					#if len(entries1) == 7:
					try:
						i = i + 1
						lsttmp=[entries1[0],entries1[2],entries1[4],entries1[5],entries1[8].strip()]
					except IndexError:
						print "incorrect packet entries1 " +  lineitem.strip()
						wrongpacket=wrongpacket + 1
				else:
						
					print " incorrect Raw Data (2016)"
					print " entries1 " + lineitem.strip()
					i = i + 1
					wrongpacket = wrongpacket + 1
					
			if cnt % 2 == 0:
				if lineitem.strip().startswith('162'):  #need to fix 162
					entries2=lineitem.split(",")
				#print lineitem
					try:
						i = i + 1 
						lsttmp=[entries2[0].strip(),entries2[1].strip()]
					except IndexError:
				 		print "incorrect packet entries2 " + lineitem.strip()
						wrongpacket=wrongpacket + 1
				else:
					print "Incorrect Raw data (162) "	
					print "entries2 "+ lineitem.strip()
					i = i + 1
					wrongpacket=wrongpacket + 1
			capturelist= capturelist + lsttmp
			if wrongpacket > 0 and i == 2:
					capturelist=[]
					i=0
					wrongpacket=0
				
			#if (i == 0 or i == 2) and (wrongpacket == 0):
			if (i == 2) and (wrongpacket == 0):
					captarray.append(capturelist)
					#print "capturelist cnt " + str(cnt)+  str(capturelist)
					capturelist=[]
					i=0
					wrongpacket=0
				
				
		
				
                                
			
			
def cleanupObject(capture,packetlist):
	i=0
	for capt in capture:
		i=i+1
	    	
		#print "capt all "+ str(capt) 
		m = re.match("([0-9]+-[0-9]+-[0-9]+\s+[0-9]+:[0-9]+:[0-9]+.[0-9]+)\s+(([a-zA-Z0-9]+:)+([a-zA-Z0-9])+)", capt[0])
		timestamp=m.group(1)  ##timestamp
		#m=re.match("length\s+([0-9]+):\s+\(tos\s+([0-9A-Za-z]+)",capt[1])
		m=re.match("length\s+([0-9]+):\s+\(tos\s+([0-9A-Za-z]+)",(capt[1].strip()))
		iplength1=m.group(1)  ## IP length1
		tos=m.group(2)  ## TOS
		m=re.match("id\s+([0-9]+)",capt[2].strip())
		id=m.group(1) # ID
		m=re.match("offset\s+([0-9]+)",capt[3].strip())
		offset=m.group(1) ## offshet
		m=re.match("length\s+([0-9]+)",capt[4])
		iplength2=m.group(1)  ### IP lenght2
		m=re.match("((([0-9]+\.){4})([0-9]+))\s*>\s*((([0-9]+\.){4})([0-9]+)): ([A-Z]+)",capt[5])
		sourceip=m.group(2).rstrip('.') ## source IP
		sourceport=m.group(4)
		destip=m.group(6).rstrip('.') ### destination IP
		destport=m.group(8)
		prot=m.group(7) ### UDP or TCP
		m=re.match("length ([0-9]+)",capt[6])
		iplength3=m.group(1) ## IP length3
		packetobj=Packet(timestamp,iplength1,tos,id,offset,iplength2,sourceip,sourceport,destip,destport,prot,iplength3)
		packetlist.append(packetobj)

def activesession(tcpipsession,packetlist):
	##print list(set(packetlist1))
	for packet in packetlist:
		tcpipsession.append(packet.tcpipsession())
	#print tcpipsession
	print list(set(tcpipsession))

def printtcpsession(tcpipsession,packetlist):
	for packet in packetlist:
		if packet.tcpipsession() == tcpipsession:
			print packet

def printwithseqId(packetlist,session,matchfunc):
	pcklst=copy.copy(packetlist)
	i=0
	idxtmp=0
	tmpid=0
	dicttmp={}
	totallst=len(pcklst)
	while i < totallst:
		temp=1000000
		for idx,packet in enumerate(pcklst):
			#print "idx " + str(idx)
			#print "packet id " + packet.id
			tmpid=int(packet.getpacketid())
			#print "temp " + str(tmpid)
			

			if tmpid < temp:
				temp=int(packet.getpacketid())
				idxtmp=idx
				#print " index " + str(idxtmp)
			
		dicttmp[i]=pcklst[idxtmp]
		#print "mid dictmp " + str(dicttmp[i]) + " and pcklst " + str(pcklst[idxtmp])
		i=i+1
		#print " index " + str(idxtmp)
		#print "lent pcklist " +  str(len(pcklst)) + " adn value of idxtmp " + str(idxtmp) + "  " + str(pcklst[idxtmp])
		del pcklst[idxtmp]
		#print "afterdelete lent pcklist " + str(len(pcklst))+ " adn value of idxtmp " + str(idxtmp) + "  " +str(pcklst[idxtmp])
		
	for key,pckt in dicttmp.items():
		#print "dictmp i " + str(i) + "  " + str(dicttmp[i])
		#print pckt.spec_session()
		#print "spect " + spec_session
		matchfunc(pckt,session)
		#if pckt.spec_session()==session:
		#		print "dictmp i " + str(key) + "  " + str(pckt)
		
		#pass
	#for packet in pcklst:
	#	print "pcklst" + str(packet)
		
		
		
def match_source_dest_ip(pckt,session):
	#print "in match source_dest ip" + pckt.spec_source_destip().strip()
	if pckt.spec_source_destip().strip() == session:
		print "sip dip " + str(pckt) + pckt.uniquenes()
		
		

def match_sourceip_sport_destip_dport(pckt,session):
	#print "sip port " + pckt.spec_session()
	
	if pckt.spec_session()==session:
		print "sip port " + str(pckt)
		
def checkdifference(pckt,packetlist2):
	#print "check diff"
	found = False
	for key,pckt2 in enumerate(packetlist2):
		if pckt.uniquenes()==pckt2.uniquenes():
			print "pckt 1: " + str(pckt)
			print "pckt 2: " + str(pckt)
			found = True
	if not found:
		print "no match : " + str(pckt)
cnt=0
flag = True

def checkpcktdrop(pckt,sipdip_session):
	global cnt,flag
	if flag:
		cnt=int(pckt.getpacketid())
		flag = False
	#print "cnt " + str(cnt) + " with packet id " + pckt.id
	if int(pckt.id) != cnt:
		print "Packet ID MISSING FROM " + str(cnt) + " TO " + (str(int(pckt.id) - 1))
		#print '\033[1;41mHighlighted Red like Radish\033[1;m'
		cnt=int(pckt.id) 
	print pckt
	cnt = cnt + 1

			
	
	
	
	
if __name__ == "__main__":
	pass
#tcpdump -tttt -v  -nnner ticker.p3p1.13.out

####loadToObject('tickers1000',captarray1)
####loadToObject('tickers5000',captarray2)
####cleanupObject(captarray1,packetlist1)
####cleanupObject(captarray2,packetlist2)
#activesession(tcpipsession,packetlist1)
#spec_session='162.8.201.1.41802 233.40.217.65.10305'
#####spec_source_dest_ip='162.8.201.1 233.40.217.65'
#printwpoithseqId(packetlist1,spec_session,match_sourceip_sport_destip_dport)
#printwithseqId(packetlist1,spec_source_dest_ip,match_source_dest_ip)
#print packetlist1
#printtcpsession('162.8.201.1.41802 233.40.217.65.10305',packetlist1)
####printwithseqId(packetlist1,packetlist2,checkdifference)


