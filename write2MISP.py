# Written by Josh Akers
# This file used for Connecting to MISP and adding the IOCs obtained from Talos' Json file directly to MISP




from pymisp import PyMISP
from pymisp import ExpandedPyMISP, MISPEvent

import argparse
import urllib3
import sys
import boto3
import logging





def ssmClientExecutionCheck(func):
    def wrapper(*args, **kwargs):
        success = False
        error = False
        for x in range(1, 5):
            try:
                value = func(*args, **kwargs)
                success = True
            except ClientError as e:
                LOGGER.error(
                    "Error in execution for %s. Error: %s" % (func.__name__, str(e))
                )
                error = e
                time.sleep(SLEEP_BASE * x)
                continue
            break

        # If the function never executed then raise the last error found
        if not success:
            LOGGER.error(
                "Too many errors found in execution of %s. Raising error back up."
                % func.__name__
            )
            raise error
        return value

    return wrapper


def createClient():
    """
    Creates the SSM client for obtaining parameters.
    """
    return boto3.client("ssm", region_name="us-east-1")




@ssmClientExecutionCheck
def getURL(ssm_client):
    """
    Obtains the URL for the MISP EC2 instance.  
    Return: string
    """
    return ssm_client.get_parameter(
        Name="/MISP/url", WithDecryption=False
    )["Parameter"]["Value"]

@ssmClientExecutionCheck
def getMISPKey(ssm_client):
    """
    Obtains the key for the MISP instance.
    Return: string
    """
    return ssm_client.get_parameter(
        Name="/MISP/key", WithDecryption=True
    )["Parameter"]["Value"]




def updateEvent(ID, iocs):
    """
    ID (int): id of the event you wish to modify
    iocs (list): List of IOCs you wish to add

    This will add IOCs to an event within MISP.  MISP has built in
    error checking for duplicates.
    """

    misp.add_attribute(ID, {'type': "ip-src", 'value': item.rstrip()}, pythonify=True)


ssmClient = createClient()
misp_url = getURL(ssmClient)
misp_key = getMISPKey(ssmClient)
misp_verifycert = False


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

misp = ExpandedPyMISP(misp_url, misp_key, False)
events = misp.events()

#Attempt to open the file containging the IOCs
#If the file doesn't exist, then the IOCs have not been added to Talos yet in the form of JSON.

try:
    fp = open("/tmp/IOCs4Clean.txt")
    lst = fp.readlines()
except:
    LOGGER = logging.getLogger()
    LOGGER.setLevel(logging.WARNING)
    LOGGER.warning("Warning: Talos hasn't added JSON file yet.")
    sys.exit(1)

fp.close()


# Logic for reading through the file to determine if the IOC is a hash, Domain, or IP.

threatName = "empty"
IPs = False
Hashes = False
Domains = False
id = events[0].get("id")
idSafe = 1

for item in lst:

    #Threat Check
    if item.find("Threat:") != -1:
        id = int(id) + 1
        threatName = item.rstrip("Threat: ")[7:]
        threatName = threatName.strip("\n")
        newEvent = MISPEvent()
        newEvent.distribution = 0
        newEvent.info = threatName
        misp.add_event(newEvent, pythonify=True)
        misp.tag(newEvent, "Talos", local=False)

    #Set IP Flag Check
    elif item.find("IPs:") != -1:
        IPs = True
        Hashes = False
        Domains = False

    #Set Domain Flag Check
    elif item.find("Domains:") != -1:
        Domains = True
        IPs = False
        Hashes = False

    #Set Hashes Flag Check
    elif item.find("Hashes:") != -1:
        Domains = False
        IPs = False
        Hashes = True
        
    #IP attribute check
    elif IPs and item.find("IPs:") == -1:

    	event = misp.add_attribute(id, {'type': "ip-src", 'value': item.rstrip()}, pythonify=True)
        
    #Domain attribute check
    elif Domains and item.find("Domains:") == -1:

    	event = misp.add_attribute(id, {'type': "domain", 'value': item.rstrip()}, pythonify=True)

    #Hash attribute check
    elif Hashes and item.find("Hashes:") == -1:

    	event = misp.add_attribute(id, {'type': "sha256", 'value': item.rstrip()}, pythonify=True)