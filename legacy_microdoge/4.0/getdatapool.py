'''
Microdog Datapool Hacker by Batteryshark

Description: The Microdog client library has a block of data that varies for each dongle serial number. 

The data itself is 112 bytes (96 bytes data, 16 bytes key). The client lib runs Rijndael (AES) over the cipher 16 bytes at a time
in CBC mode with our key to produce a datapool of sorts.

This program dumps that data from a specified file or changes
the datapool to something else (this would let you use a 
different dongle for any program that uses the library).

For input, we need the operation desired (extract or convert), an input binary, an output path, the offset where the datapool starts (varies greatly), and an input 96 byte plaintext block if you're converting.

For future reference, these are the ones I tested:

MOST of the .o files themselves are 0xB500 
(including infinity).

NXA 1.09 | 0xF7EE0


NOTE: Microdog 3.4 uses a different algorithm and I'm too lazy to figure out how
to decrypt it. The tool will detect the microdog lib as 3.4 if the offset starts
with the identifying flag "NEIWAIJM" and will dump encrypted and subsequently convert
by copying the data over another 3.4 file.
'''

import os,sys,struct,rijndael

#Static Globals
OFFSET_SN = 0x1A
OFFSET_DOGID_LO = 0x26
OFFSET_DOGID_HI = 0x2C
MH40_DATAPOOL_SIZE = 96
MH40_KEY_SIZE = 16
MH34_DATAPOOL_SIZE = 0x28B
#Non Static Globals
datapool_offset = 0

def extract_data():
	
	f = open(sys.argv[2],"rb")
	f.seek(datapool_offset,0)
	
	md34test = f.read(8)
	f.seek(datapool_offset,0)
	if("NEIWAIJM" == md34test):
		print("Microdog 3.4 Library Detected.")
		decdata = f.read(MH34_DATAPOOL_SIZE)
		f.close()
	else:
		encdata = f.read(MH40_DATAPOOL_SIZE)
		decdata = ""
		key = f.read(MH40_KEY_SIZE)
		f.close()
		#Decryption
		r = rijndael.rijndael(key)
		for i in range(0,MH40_DATAPOOL_SIZE,16):
			decdata+= r.decrypt(encdata[i:i+16])
		dog_id = struct.unpack("<I",decdata[OFFSET_SN:OFFSET_SN+4])[0]
		dog_data = struct.unpack(">Q",decdata[OFFSET_DOGID_LO:OFFSET_DOGID_LO+4]+decdata[OFFSET_DOGID_HI:OFFSET_DOGID_HI+4])[0]
		print("DogID: %04x" % dog_id)
		print("Dogdata: %08x" % dog_data)
	
	#Write decrypted output to file.
	f = open(sys.argv[3],"wb")
	f.write(decdata)
	f.close()
	print("Wrote decrypted datapool to disk.")
	exit(0)
	
def convert_data():
	#Get target key
	f = open(sys.argv[2],"rb")
	
	f.seek(datapool_offset,0)
	md34test = f.read(8)

	#Make a copy of our input file.
	f.seek(0,0)
	outdata = f.read()
	
	if("NEIWAIJM" == md34test):
		print("Microdog 3.4 Library Detected.")
		encdata = f.read(MH34_DATAPOOL_SIZE)
		outdata = outdata[:datapool_offset] + encdata + outdata[datapool_offset+MH34_DATAPOOL_SIZE:]
		f.close()
		
	else:
		f.seek(datapool_offset+MH40_DATAPOOL_SIZE,0)
		key = f.read(MH40_KEY_SIZE)
		f.close()

		
		#Get target data
		f = open(sys.argv[5],"rb")
		decdata = f.read()
		f.close()
			
		#Encrypt target data with key
		r = rijndael.rijndael(key)
		encdata = ""
		for i in range(0,MH40_DATAPOOL_SIZE,16):
			encdata+= r.encrypt(decdata[i:i+16])
		
			#Modify our in-memory binary copy with the new data.
			outdata = outdata[:datapool_offset] + encdata + outdata[datapool_offset+MH40_DATAPOOL_SIZE:]
		
	#Write modified binary to file.
	f = open(sys.argv[3],"wb")
	f.write(outdata)
	f.close()


def usage():
	print("Usage: %s e/c [infile] [outfile] [offset] (indogdata) " % sys.argv[0])
	exit(1)
if(__name__=="__main__"):
	if(len(sys.argv) < 4):
		usage()
	if(sys.argv[1] != "e" and sys.argv[1] != "c"):
		usage()
	if(sys.argv[1] == "c" and len(sys.argv) < 5):
		usage()
	
	if("0x" in sys.argv[4]):
		datapool_offset = int(sys.argv[4][2:],16)
	else:
		datapool_offset = int(sys.argv[4])
	
	
	if(sys.argv[1] == "e"):
		extract_data()
	
	if(sys.argv[1] == "c"):
		convert_data()