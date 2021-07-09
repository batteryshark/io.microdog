'''
Super Simple Microdog 3.4 Emulator by Batteryhark
'''

import os,sys,socket,microdog,struct
UDP_IP = "0.0.0.0"
UDP_PORT = 57301
sock = socket.socket(socket.AF_INET, # Internet
                    socket.SOCK_DGRAM) # UDP
sock.bind((UDP_IP, UDP_PORT))


print("Microdog 3.4 Emulator by Batteryshark")
print("Listening on Port %s" % UDP_PORT)

md = microdog.Microdog()

while True:
 data, addr = sock.recvfrom(280)
 response = md.process(bytearray(data))
 sock.sendto(response, addr)