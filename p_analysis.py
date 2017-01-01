from packet import *
import getopt,sys

captarray1=[]
captarray2=[]
packetlist1=[]
packetlist2=[]
tcpipsession=[]
loadToObject('tickers5000A',captarray1)
cleanupObject(captarray1,packetlist1)
loadToObject('tickers1000',captarray2)
cleanupObject(captarray2,packetlist2)

def printallsession():
	activesession(tcpipsession,packetlist1)
	for pckt in list(set(tcpipsession)):
		print str(pckt)
	#spec_session='162.8.201.1.41802 233.40.217.65.10305'
	#printtcpsession(spec_session,packetlist1)
	
def printspecificflow(spec_session):
	printwithseqId(packetlist1,spec_session,match_sourceip_sport_destip_dport)

def printsiptodip(sipdip):
	printwithseqId(packetlist1,sipdip,match_source_dest_ip)
	
def printdifference():
	printwithseqId(packetlist1,packetlist2,checkdifference)

def checkpacketmissing(sipdip):
	printwithseqId(packetlist1,sipdip,checkpcktdrop)
		

#loadToObject('tickers5000',captarray2)

#cleanupObject(captarray2,packetlist2)
#activesession(tcpipsession,packetlist1)
#spec_session='162.8.201.1.41802 233.40.217.65.10305'
#####spec_source_dest_ip='162.8.201.1 233.40.217.65'
#printwpoithseqId(packetlist1,spec_session,match_sourceip_sport_destip_dport)
#printwithseqId(packetlist1,spec_source_dest_ip,match_source_dest_ip)
#print packetlist1
#printtcpsession('162.8.201.1.41802 233.40.217.65.10305',packetlist1)
####printwithseqId(packetlist1,packetlist2,checkdifferen

def usage():
	print "p_analysis -u for printing all active session"
	print 'p_analysis -s "162.8.201.1.41802 233.40.217.65.1035" for printing all packet for specific sport sip to dip dport'
	print 'p_analysis -p "162.8.201.1 233.40.217.65.10"'
	print "p_analysis -d different between 2 capture"
	print 'p_analysis -d "162.8.201.1 233.40.217.65.10" for checking missing packet based on packet ID'
	
try:
	opts, args = getopt.getopt(sys.argv[1:], "hcus:p:d:")		#opts, args = getopt.getopt(sys.argv[1:], "ho:v", ["help", "output="])
except getopt.GetoptError as err:
	print str(err)  
	usage()
	sys.exit(2)
		
for o, a in opts:
		if o == "-h":
			usage()
			sys.exit(0)
		elif o == "-u":
			printallsession()
		elif o == "-s":
			#spec_session='162.8.201.1.41802 233.40.217.65.10305'
			#print "in session " +a
			printspecificflow(a)
		elif o == "-p":
			#spec_session='162.8.201.1.41802 233.40.217.65.10305'
			#print "in sip dip session " + a
			printsiptodip(a)
		elif o == "-c":
			printdifference()
		elif o == "-d":
			checkpacketmissing(a)
		else:
			#assert False, "unhandled option"
			sys.exit(2)
		 
		#lif o == "-a
		#adding account=true
		#	adding account=true
        #else:
        #    assert False, "unhandled option"