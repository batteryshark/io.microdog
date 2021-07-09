'''
Pump it Up Test Vector Extractor

Exceed 2 - FiestaEX Use 100 dongle transactions to validate proper operation of the Microdog.
The first operation is used when the game starts to determine if "WAITING LOCK DEVICE" or
"LOCK ERROR" should be shown; the rest are used in the SETUP menu where you see "LOCK OK"
and "LOCK ERR". The values are stored statically in a table within the game's binary.

This tool, given a binary file, offset to the table, and an optional flag to hash the
request will read the test vectors from the file and print them via stdout.
'''
import os,sys,struct,md5, binascii

#Every game has the same number.
NUM_VECTORS = 100
ENTRY_SIZE = 68
type2 = False
def usage():
	print("Usage: %s [infile] [offset] (optional 2 for md5hash)")
	exit(1)
	
if(__name__=="__main__"):
	if(len(sys.argv) < 3):
		usage()
		
	f = open(sys.argv[1],"rb")
	if("0x" in sys.argv[2]):
		offset = int(sys.argv[2].replace("0x",""),16)
	else:
		offset = int(sys.argv[2])
	f.seek(offset,0)
	
	
	if(len(sys.argv) > 3):
		type2 = True
	
	for i in range(0,NUM_VECTORS):
		response = struct.unpack("<I",f.read(4))[0]
		req_size = struct.unpack("<I",f.read(4))[0]
		request = f.read(ENTRY_SIZE - 8)
		request = request[:req_size]
		if(type2 == True):
			m = md5.new()
			m.update(request)
			request = m.digest()
		print("c %04x %s" % (response,binascii.hexlify(request)))