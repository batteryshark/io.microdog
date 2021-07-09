'''
Pump it Up Test Vector Extractor
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