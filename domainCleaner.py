#
# Author: Josh Akers
# Description: Servers as a whitelisting method for making sure common domains are not added as an IOC to MISP.
#
# 
# To do: Add proper logging and remove the silly print statements.

import sys
import os
import logging




# Attempt to read in the IOCs
try:
	name = sys.argv[1]
	with open(name) as f:
	    IOCs = f.readlines()

# File doesn't exist because JSON wasn't added to Talos.  
except:
	try:
		# Don't recall what this nested try here is for.  
		os.remove("/tmp/IOCs4Clean.txt")
	except:
		#Continuing to allow for a clean fail later on.  
		sys.exit(1)
	sys.exit(1)


IOCs = [x.strip() for x in IOCs] 


with open("whitelistN.txt") as a:
    domains = a.readlines()

domains = [x.strip() for x in domains] 


for item in IOCs:
	if item in domains:
		IOCs.remove(item)


f = open("/tmp/IOCs4Clean.txt", "w")
for item in IOCs:
	f.write(item + "\n")


f.close()