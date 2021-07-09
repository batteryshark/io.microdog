# Microdog Data Extractor for 3.4
import os,sys,binascii,struct

# There's no need to reverse the algorithm due
# to the fact that it just adds, subtracts, or
# XORs the bytes in sequence against the 
# current - meaning 0 in every case has
# no effect on the plaintext->ciphertext.

def enc_vals(indata):
	out = bytearray(len(indata) * 12)
	for i in range(0,len(indata)):
		out[i*12] = indata[i]
	return out
	
def get_serial(indata):
	out = bytearray(4)
	v3 = 0
	for i in range(0,4):
		out[i] = 0
		for j in range(0,12):
			v2 = j % 3
			if(j % 3 == 1):
				out[i] = (out[i] - indata[v3]) & 0xFF 
				v3 +=1
			elif(v2 > 1):
				if(v2 == 2):
					
					out[i] ^= indata[v3]
					v3 +=1
			elif(v2 == 0):
				out[i] = ( out[i] + indata[v3]) & 0xFF
				v3 +=1
	return out


def get_dog_id(indata):
	out = bytearray(8)
	v3 = 0
	for i in range(0,8):
		out[i] = 0
		for j in range(0,12):
			v2 = j % 3
			if(j % 3 == 1):
				out[i] ^= indata[v3] 
				v3 +=1
			elif(v2 > 1):
				if(v2 == 2):
					out[i] = (out[i] - indata[v3]) & 0xFF
					v3 +=1
			elif(v2 == 0):
				out[i] = ( out[i] + indata[v3]) & 0xFF
				v3 +=1
	return out

if(len(sys.argv) < 3):
	print("Usage %s e/r [infile] (r-hexserial) (r-hexdogid)" % sys.argv[0])
	exit(1)
f = open(sys.argv[2],'rb')
indata = f.read()
f.close()
info_buffer_offset = indata.find("NEIWAIJM")
if(info_buffer_offset == -1):
	print("Error! Info Buffer Tag Not Found!")
	exit(1)

serial_offset = info_buffer_offset + 270
dog_id_offset = serial_offset + 202
	
if(sys.argv[1] is "e"):
	#Offset of where DogID Starts
	dog_id_data = bytearray(indata[dog_id_offset: dog_id_offset + 96])
	serial_data = bytearray(indata[serial_offset:serial_offset+48])
	print("# %s Serial Extraction" % sys.argv[2])
	print("i %04x %s" % (struct.unpack("<I",get_serial(serial_data))[0], binascii.hexlify(get_dog_id(dog_id_data))))
else:
	#Repack
	try:
		new_serial = struct.pack("<I",int(sys.argv[3].replace("0x",""),16))
	except:
		print("Serial must be in hex digit form.")
		exit(1)
	
	new_dog_id = binascii.unhexlify(sys.argv[4])
	if(len(new_dog_id) != 8):
		print("Dog ID must be 16 bytes.")
		exit(1)
	

	indata = indata[:serial_offset]+ enc_vals(new_serial) + indata[serial_offset + 48 :dog_id_offset] + enc_vals(new_dog_id) + indata[dog_id_offset + 96:]

	f = open(sys.argv[2]+"_repacked","wb")
	f.write(indata)
	f.close()
	