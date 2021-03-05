#
# Author: Josh Akers
# Descirption: Given a json file from Talos, this will obtain all of the threats 
# and their respective IOCs from it and write to a file.
#
# Todo: Better Comments


import json
import sys


name = sys.argv[1]


try:
    data = json.loads(open(name).read())
except:
    sys.exit(1)




data.pop("exprev")
data.pop("info")
data.pop("signatures")
mykey = data.keys()
write = sys.argv[2]
f = open(write, "w")



for k in mykey:
    f.write("Threat: " + k)
    f.write("\n")
    f.write("IPs: \n")
    
    #Grab the IPs
    for item in data[k].get("iocs").get("ip"):
        result = str(item.get("ip")).replace('[', '').replace(']', '')
        f.write(result + "\n")
    f.write("Domains: " + "\n")
    #Grab the domains
    for item in data[k].get("iocs").get("domain"):
        result = str(item.get("host")).replace('[', '').replace(']', '')
        
        f.write(result + "\n")
    
    #Grab the hashes
    
    f.write("Hashes: " + "\n")
    for item in data[k].get("hashes"):
        
        f.write(item + "\n")
    f.write("*\n")
        
    


f.close()

