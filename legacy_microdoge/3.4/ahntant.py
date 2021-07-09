#Microdog Rainbow Table format Converter 1.0
#Converts Ahnada's Format to tau's Format

import os,sys

with open(sys.argv[1]) as f:
	lines = f.readlines()
	for line in lines:
		elements = line.strip().split(",")
		if(len(elements) == 3):
			print("c %s %s" % (elements[0].lower() ,elements[2].lower()))
		