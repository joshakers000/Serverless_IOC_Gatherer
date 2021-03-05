# Author: Josh Akers
# File is used pull down the weekly threat blog post roundup from talos and submit them the MISP.
#

import requests
import subprocess
from datetime import date
import os
import sys
import logging
import math
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)




def lambda_handler(event, context):
	today = date.today()
	month = (today.strftime("%m"))
	year = (today.strftime("%Y"))
	day = (today.strftime("%d")) 


	# If it's the first of the month
	if(int(day) == 1):
		#February
		if(int(month) == 3):
			if(int(year)/4 < math.ceil(int(year)/4)):
				day = "28"
			else:
				day = "29"
		#30 day months (add 1 to each month because it's the first of the next month)
		#April, June, September, Novmeber
		elif(int(month) == 5 or int(month) == 7 or int(month) == 10 or int(month) == 12):
			day = "30"
		#All the other months
		else:
			day = "31"
		#subtract 1 from month.
		if (int(month) == 1):
			month = str(12)
		else:
			month = str(int(month) - 1)
	else:
		day = str(int(day) - 1)
	


	if(len(month) == 1):
		month = "0" + month

	print("Month: " + month)
	print("Day: " + day)
	print("Year: " + year)

	if(len(month) == 1):
		month = "0" + month



	page = requests.get("https://storage.googleapis.com/blogs-images/ciscoblogs/1/" + year + "/" + month + '/'+ year + month + day + '-tru.json_.txt')

	


	#Create the names for the json file and text file
	jsonName = today.strftime("/tmp/%m%d.json")
	textName = today.strftime("/tmp/%m%d.txt")

	#pull down context, and write to the json file, then close file.
	f = open(jsonName, "w")
	content = page.text
	f.write(content)
	f.close()

	#Convert Json to text
	os.system("python3 threatscript.py " + jsonName + " " + textName)

	#Clean the domains
	os.system("python3 domainCleaner.py " + textName)



	#Call test.py
	os.system("python3 write2MISP.py")


if __name__ == "__main__":

    class ContextFake:
        """This is a fake class used to populate the context method"""

        log_stream_name = "TESTING CODE"
        pass

    context = ContextFake()
    LOGGER.addHandler(logging.StreamHandler())
    LOGGER.setLevel(logging.INFO)
    event = {
    }
    lambda_handler(event, context)
