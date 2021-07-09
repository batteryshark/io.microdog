#Husky Microdog Emulator by poiz0n3 :: RiDEorDIE

import os,sys,md5,socket,struct,rijndael,binascii

SOCK_NAME = "/var/run/microdog/u.daemon"
PACKET_LEN = 596
PROTOCOL_VERSION = 0x11
REQHEAD_SIZE = 0x120
REQTAIL_SIZE = 0x10
REQPACKET_SIZE = REQHEAD_SIZE + REQTAIL_SIZE 
PACKET_MAGIC = 0x484D

REQ_SET_SHARE = 0x08
REQ_GET_LOCK_NO = 0x0B
REQ_GET_ID = 0x14
REQ_CONVERT = 0x40
REQ_AUTHENTICATE_STEP1 = 0x65
REQ_AUTHENTICATE_STEP2 = 0x67
REQ_AUTHENTICATE_STEP3 = 0x66
DEBUG = True
SHARED_KEY = "\x2A\x2F\xED\x5E\x49\x26\x40\x19\x40\x40\xE2\x51\xAA\xFA\xDB\xCB\x67\x21\x4C\xA4\x10\x7E\x51\x22\x25\x11\x2B\x3C\x46\x5E"
#This is an MD5 of the Shared key above... makes sense to memoize it.
MD5_SECRET = "\x35\xFC\xF5\x34\xC7\x20\x55\x11\xA4\x59\x16\x20\x1F\x48\xE5\x5E"

def aes_decrypt(indata,size,key):
	#Decryption
	decdata = ""
	r = rijndael.rijndael(key)
	for i in range(0,size,16):
		decdata+= r.decrypt(indata[i:i+16])
	return decdata
def aes_encrypt(indata,size,key):
	#Encryption
	encdata = ""
	r = rijndael.rijndael(key)
	for i in range(0,size,16):
		encdata+= r.encrypt(indata[i:i+16])
	return encdata

def md5_hash(data):
    m = md5.new()
    m.update(data)
    return m.digest()


class Time_Key:
	def __init__(self):
		self.ssk_prefix = bytearray(25)
		self.year = 0
		self.c45 = 45
		self.month = 0
	def serialize(self):
		return self.ssk_prefix + struct.pack("<H",self.year)+\
		struct.pack("B",self.c45) + struct.pack("<H",self.month)

def get_time_key(ts):
	global cache_tk
	tk = Time_Key()
	tk.ssk_prefix = SHARED_KEY[:25]
	tk.year =  ts.ts_year
	tk.month = ts.ts_month
	tk.c45 = 45


	#Construct Key	
	return md5_hash(tk.serialize())



class Transaction:
	def __init__(self,packet,md):
	    self.state = True
	    #Decrypt our request to find out wtf.
	    packet.request = packet.request.decrypt()
	    
	    packet.response.rs_req_type = packet.request.rq_req_type
	    #Send our request to the fake dongle.
	    result = self.dispatch(packet,md)
	    if(result):
	      packet.header = 0
	      #Repack response to send back to program.
	    
	      packet.response = packet.response.encrypt(packet.request.ts)
	    else:
	      packet.header = 20023
	    self.newpacket = packet
	def retpacket(self):
	        return self.newpacket
	def send_lock_no(self,req,resp,serial):
		#Passing back a static dongle serial, huehuehue.
		if(serial is 0xDEADBEEF):
		  resp.rs_data = struct.pack("<I",0x116355A)+resp.rs_data[4:]
		else:
		  resp.rs_data = struct.pack("<I",serial)+resp.rs_data[4:]

	def auth3(self,req,resp):
		key = get_time_key(req.ts)
		resp.data = aes_encrypt(req.rq_data,16,key)
	def send_dog_id(self,resp,dog_id):
		
		resp.rs_data = dog_id.decode("hex") + resp.rs_data[8:]
		return resp
	def convert(self,req,resp,tbl):
	
		reqval = binascii.hexlify(req.rq_data[:req.rq_data_size])
		#Return Null if Key not Found
		try:
			resp.rs_data = struct.pack("<I",tbl[reqval]) + resp.rs_data[4:]
			print("%s -> %#04x" % (reqval,tbl[reqval]))
		except KeyError:
			print("Request %s not found! Sending Null" % reqval)
			resp.rs_data = struct.pack("<I",0x00000000) + resp.rs_data[4:]
	def dispatch(self,packet,md):	

		if(packet.request.rq_req_type == REQ_SET_SHARE):
			print("Share flag set to %02X" % struct.unpack("B",packet.request.rq_data[0])[0])
			return True
		if(packet.request.rq_req_type == REQ_GET_LOCK_NO):
			print("Sending Lock Number")
			self.send_lock_no(packet.request,packet.response,md.dog_serial)
			return True
		
		if(packet.request.rq_req_type == REQ_GET_ID):
			print("Get Dongle ID")
			packet.response = self.send_dog_id(packet.response,md.dog_id)
			#packet.response.dump()
			return True
		if(packet.request.rq_req_type == REQ_CONVERT):
			
			print("DogConvert()")
			self.convert(packet.request,packet.response,md.dog_table)
			#packet.response.dump()
			return True
		if(packet.request.rq_req_type == REQ_AUTHENTICATE_STEP1):
			print("Auth Step 1")
			return True		
		if(packet.request.rq_req_type == REQ_AUTHENTICATE_STEP2):
			print("Auth Step 2")
			return True
		if(packet.request.rq_req_type == REQ_AUTHENTICATE_STEP3):
			self.auth3(packet.request,packet.response)
			return True
		print("Unknown Request code %02X" % packet.request.rq_req_type)
		return False
		
class MD_Response:
	def __init__(self,data):
		self.rs_magic = struct.unpack("<H",data[0:2])[0]
		self.rs_mask1 = struct.unpack("<I",data[2:6])[0]
		self.rs_req_type = struct.unpack("B",data[6])[0]
		self.rs_mask2 = struct.unpack("<I",data[7:11])[0]
		self.rs_kernel_retval = struct.unpack("<I",data[11:15])[0]
		self.rs_mask3 = struct.unpack("<I",data[15:19])[0]
		self.rs_data = data[19:275]
		self.rs_mask4 = struct.unpack("<I",data[275:279])[0]
		self.rs_pad = data[279:]
	def getsz(self):
		return 288
	def dump(self):
		print(vars(self))
	def serialize(self):
		return struct.pack("<H",self.rs_magic) + struct.pack("<I",self.rs_mask1) + struct.pack("B",self.rs_req_type) + struct.pack("<I",self.rs_mask2) + struct.pack("<I",self.rs_kernel_retval) + struct.pack("<I",self.rs_mask3) + self.rs_data + struct.pack("<I",self.rs_mask4) + self.rs_pad 
	def encrypt(self,ts):
		
		key = get_time_key(ts)
		return MD_Response(aes_encrypt(self.serialize(),self.getsz(),key))

class Timestamp:
	def __init__(self,data):
		self.ts_year = struct.unpack("<H",data[0:2])[0]
		self.ts_month = struct.unpack("<H",data[2:4])[0] 
		self.ts_day = struct.unpack("<H",data[4:6])[0]
		self.ts_hour = struct.unpack("<H",data[6:8])[0]
		self.ts_minute = struct.unpack("<H",data[8:10])[0]
		self.ts_second = struct.unpack("<H",data[10:12])[0]
		self.ts_pad = data[12:15]	

class MD_Request:
	def __init__(self,data):
		self.rq_magic = struct.unpack("<H",data[0:2])[0]
		self.rq_req_type = struct.unpack("B",data[2])[0]
		self.rq_mask1 = struct.unpack("<I",data[3:7])[0]
		self.rq_dog_cascade = struct.unpack("B",data[7])[0]
		self.rq_hw_serial = struct.unpack("<I",data[8:12])[0]
		self.rq_mask2 = struct.unpack("<I",data[12:16])[0]
		self.rq_dog_addr = struct.unpack("<H",data[16:18])[0] 
		self.rq_data_size = struct.unpack("<H",data[18:20])[0]
		self.rq_mask3 = struct.unpack("<I",data[20:24])[0]
		self.rq_data = data[24:280]
		self.rq_dog_password = struct.unpack("<I",data[280:284])[0]
		self.rq_host_id = struct.unpack("B",data[284])[0]
		self.rq_mask4 =struct.unpack("<I",data[285:289])[0]
		self.ts = Timestamp(data[289:304])
	def dump(self):
		print(vars(self))
	def serialize(self):
		data =    struct.pack("<H",self.rq_magic)
		data +=   struct.pack("B",self.rq_req_type)
		data +=   struct.pack("<I",self.rq_mask1)
		data +=   struct.pack("B",self.rq_dog_cascade & 0xFF)
		data +=   struct.pack("<I",self.rq_hw_serial)
		data +=   struct.pack("<I",self.rq_mask2)
		data +=   struct.pack("<H",self.rq_dog_addr)
		data +=   struct.pack("<H",self.rq_data_size)
		data +=   struct.pack("<I",self.rq_mask3)
		data +=   self.rq_data
		data +=   struct.pack("<I",self.rq_dog_password)
		data +=   struct.pack("B",self.rq_host_id & 0xFF)
		data +=   struct.pack("<I",self.rq_mask4)
		data +=   struct.pack("<H",self.ts.ts_year)
		data +=   struct.pack("<H",self.ts.ts_month)
		data +=   struct.pack("<H",self.ts.ts_day)
		data +=   struct.pack("<H",self.ts.ts_hour)
		data +=   struct.pack("<H",self.ts.ts_minute)
		data +=   struct.pack("<H",self.ts.ts_second)
		data +=	  self.ts.ts_pad
		return data
	      
	def getsz(self):
		return 304
	def decrypt(self):
	  #Decrypt that key with AES and load the result into a
	  #new decrypted request buffer.
	  data = self.serialize()
	  tail_tmp = aes_decrypt(data[REQHEAD_SIZE:],REQTAIL_SIZE,MD5_SECRET)
	  #We're gonna do a little Swaparoo because we need the proper year
	  #to feed the generation of the time key.
	  self.ts = Timestamp(tail_tmp[1:])
	  head_tmp = aes_decrypt(data[:REQHEAD_SIZE],REQHEAD_SIZE,get_time_key(self.ts))
	  data = head_tmp+tail_tmp
	  self = MD_Request(data)
	  
	  #Decrypt Elements
	  self.rq_magic ^= self.rq_mask4
	  self.rq_req_type ^= self.rq_mask4
	  self.rq_mask1 ^= self.rq_mask4
	  self.rq_dog_cascade ^= self.rq_mask4
	  self.rq_hw_serial ^= self.rq_mask4
	  self.rq_mask2 ^= self.rq_mask4
	  self.rq_dog_addr ^= self.rq_mask4
	  self.rq_data_size ^= self.rq_mask4
	  self.rq_mask3 ^= self.rq_mask4
	  self.rq_dog_password ^= self.rq_mask4
	  self.rq_host_id ^= self.rq_mask4
	  
	  newdata = ""
	  for i in range(0,256,4):
		  val = struct.unpack("<I",self.rq_data[i:i+4])[0] ^ self.rq_mask4
		  newdata += struct.pack("<I",val)
	  self.rq_data = newdata


	  self.rq_magic ^= self.rq_mask3;
	  self.rq_req_type ^= self.rq_mask3;
	  self.rq_mask1 ^= self.rq_mask3;
	  self.rq_dog_cascade ^= self.rq_mask3;
	  self.rq_hw_serial ^= self.rq_mask3;
	  self.rq_mask2 ^= self.rq_mask3;
	  self.rq_dog_addr ^= self.rq_mask3;
	  self.rq_data_size ^= self.rq_mask3;
	  
	  self.rq_magic ^= self.rq_mask2;
	  self.rq_req_type ^= self.rq_mask2;
	  self.rq_mask1 ^= self.rq_mask2;
	  self.rq_dog_cascade ^= self.rq_mask2;
	  self.rq_hw_serial ^= self.rq_mask2;
	  
	  self.rq_magic ^= self.rq_mask1;
	  self.rq_req_type ^= self.rq_mask1;	
	  
	  if(self.rq_magic != PACKET_MAGIC):
		  print("Packet Magic Doesn't Match!")
	  return self
class MD_Packet:
	def __init__(self,data):
		#State ID to check for invalid COMM
		self.state = "BAD"
		#Packet Magic
		self.header = struct.unpack("<I",data[0:4])[0]
		#Request Data
		self.request = MD_Request(data[4:308])
		#Response Data
		self.response = MD_Response("\x00" * 288)
		self.response.rs_magic = PACKET_MAGIC
		
		
	#Construct bytearray from packet data for transmission.
	def serialize(self):
		return struct.pack("<I",self.header) + self.request.serialize() + self.response.serialize()


class Microdog:
	def __init__(self):
		self.node_name = "/var/run/microdog/u.daemon"
		self.dog_id = ""
		self.dog_key = 0xBADDDEAD
		self.dog_serial = 0xDEADBEEF
		self.dog_platform = "Linux"
		self.dog_table = {}
		self.md_version = "4.0"
		if not os.path.exists("/var/run/microdog"):
			os.makedirs("/var/run/microdog")
		self.load_info()
		
	#Reads dongle data from descriptor table.
	def load_info(self):
		with open(sys.argv[1]) as f:
			lines = f.readlines()
			for line in lines:
				line = line.strip()
				if(not "#" in line):
					elements = line.split(" ")
					if(len(elements) == 3):
						if(elements[0] == "i"):
							self.dog_id = elements[2]
							self.dog_key = int(elements[1],16)
						if(elements[0] == "c"):
							self.dog_table[elements[2]] = int(elements[1], 16)
						if(elements[0] == "s"):
							self.dog_serial = int(elements[1],16)
						if(elements[0] == "v"):
							self.md_version = elements[1]
							self.dog_platform = elements[2]

		print("Loaded Microdog Version %s" % self.md_version)
		print("Dog Name: %s" % self.dog_platform)
		print("Dog Key: %04X" % self.dog_key)
		print("DogID: %s\nDogSerial:%04x" % (self.dog_id,self.dog_serial))
		print("Loaded %d Keys\n" % len(self.dog_table))	



if(__name__=="__main__"):
	if(os.name is "nt"):
		print("This program is not compatible with Windows.")
		exit(1)
	if(len(sys.argv) < 2):
		print("Usage %s data.txt" % sys.argv[0])
		exit(1)
	if(not os.path.exists(sys.argv[1])):
		print("Invalid dongle data file")
		exit(1)
	print("\nHusky Microdog Emulator by Batteryshark")
	md = Microdog()
	#packet = MD_Packet()
	#Set up the socket
	if(os.path.exists(SOCK_NAME)):
		os.remove(SOCK_NAME)
	sock = socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)
	sock.bind(SOCK_NAME)
	#Dongle Comm Wait Loop
	while True:
		data,peer = sock.recvfrom(PACKET_LEN)
		if(data == -1):
			print("ERROR: Bad File Descriptor!")
			break
		if(len(data) != PACKET_LEN):
			print("ERROR: Truncated Packet")
			break
		#Initialize our packet and make transactions.
		packet = MD_Packet(data)
		if(packet.header != PROTOCOL_VERSION):
			print("Protocol Version Mismatch!")
			print("Expected 0x11, got %X" % packet.header)
			continue
		if(DEBUG is True):
			print("Packet Received!")
		#	print("Version 0x%X Size:%d bytes" % (packet.header,len(data)))
		xtn = Transaction(packet,md)
		packet = xtn.retpacket()
		if(xtn.state is True):
		#	print("Sending response to %s" % peer)
			sock.sendto(packet.serialize(),peer)
			del packet
			del xtn
		#	print("Send complete!")

	print("Emulator Shutdown")
	os.unlink(SOCK_NAME)
