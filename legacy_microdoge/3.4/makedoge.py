'''
makedoge - Generate a Microdog doge.key file
and import keys from a rainbow table (optional)
'''

import os,sys,struct,binascii

print("Generating doge.key")

dog_serial = 0
dog_password = 0
vendor_id = ""
mfg_serial = 0
dog_flashmem = bytearray(200)
num_keys = 0
dog_table = {}

with open(sys.argv[1]) as f:
	lines = f.readlines()
	for line in lines:
		line = line.strip()
		if(not "#" in line):
			elements = line.split(" ")
			if(len(elements) > 1):
				if(elements[0] == "i"):
					vendor_id = elements[2]
					dog_serial = int(elements[1],16)
				if(elements[0] == "p"):
					dog_password = int(elements[1],16)
				if(elements[0] == "s"):
					mfg_serial = int(elements[1],16)
				if(elements[0] == "a"):
					dog_flashmem[196:] = struct.pack("<I",int(elements[1],16))
				if(elements[0] == "e"):
					#This is pretty gross - don't do this.
					dog_table[(elements[1],elements[3])] = int(elements[2], 16)


print("Dog Key: %04X" % dog_serial)
print("DogID: %s\nDogSerial:%04x" % (vendor_id,mfg_serial))
print("Loaded %d Keys\n" % len(dog_table))	

key_data = ""
key_data += struct.pack("<I",dog_serial)
key_data += struct.pack("<I",dog_password)
key_data += binascii.unhexlify(vendor_id)
key_data += struct.pack("<I",mfg_serial)
key_data += dog_flashmem
key_data += struct.pack("<I",len(dog_table))
for (curr_algorithm,req_str) in dog_table.keys():
	request = binascii.unhexlify(req_str)
	key_data += struct.pack("<I",dog_table[(curr_algorithm,req_str)])
	key_data += struct.pack("<I",int(curr_algorithm,16))
	key_data += struct.pack("<I",len(request))
	key_data += request + bytearray(64- len(request))
f = open("doge.key","wb")
f.write(key_data)
f.close()
