#GetID Python Port
import libusb1,os,sys,struct
from ctypes import *

VID = 0x08E2
PID = 0x0002
buf =  create_string_buffer(8)

libusb1.libusb_init(None)   
hdev = libusb1.libusb_open_device_with_vid_pid(None,VID,PID)   
libusb1.libusb_get_descriptor(hdev, 3, 3, buf, 8);

buf = bytearray(buf)
dog_id = struct.unpack("<I",buf[:3]+"\x00")[0]
dog_id += 0xC5C10 #Magic Value


print("DogID: %0#x" % dog_id)
print("Raw Data: %08X" % struct.unpack(">Q",buf)[0])     
libusb1.libusb_close(hdev);
libusb1.libusb_exit(None)
     