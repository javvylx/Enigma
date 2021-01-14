import re
import os
import subprocess
import string
import socket
from bs4 import BeautifulSoup
import ipaddress
import requests
import random
import csv
import hashlib
from datetime import datetime

mainDir = os.getcwd()+"\\Cases"
vol = "volatility-2.6.standalone.exe"
volatility = mainDir+ "\\volatility_2.6_win64_standalone.exe"
#Placeholder
imagePath = mainDir + "\\test.raw"
casefolder = " "
 
user_agent_list = [
	'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15',
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:77.0) Gecko/20100101 Firefox/77.0',
	'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36',
	'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:77.0) Gecko/20100101 Firefox/77.0',
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36',
]


def analysis(casename,ramImagePath):

	global casefolder
	global imagePath
	currentDate = datetime.now()
	dt_string = currentDate.strftime("%d-%m-%Y_%H-%M-%S")
	casefolder = mainDir+ "\\"+ dt_string+"_"+casename
	try:
		os.mkdir(casefolder)
		if os.path.exists(ramImagePath):
			imagePath = ramImagePath
			RAM_imageinfo(imagePath)
			ProfileList = get_profile()
			get_process_tree(ProfileList[0])
			get_netscan(ProfileList[0])
			iplist = getPublicIp()
			ipWhoISLookUp(iplist)
			get_cmdscan(ProfileList[0])
			get_processdump(ProfileList[0])
			get_dlldump(ProfileList[0])
			print("Done")


	except:
		return -1
	



def file_hash_hex(file_path, hash_func):

	with open(file_path, 'rb') as f:
		return hash_func(f.read()).hexdigest()

def recursive_file_listing(base_dir):

	for directory, subdirs, files in os.walk(base_dir):
		for filename in files:
			yield directory, filename, os.path.join(directory, filename)




def RAM_imageinfo(path):

	global casefolder
	imageInfoCommand = volatility + " -f " + path + " imageinfo > " + casefolder +"\\ImageInfo.txt"
	output = subprocess.run(imageInfoCommand, shell=True)



def get_profile():

	global casefolder
	with open(casefolder +'\\ImageInfo.txt') as f:
		suggested_profile = f.readline()
		f.close()
	suggested_profile = suggested_profile.rstrip()
	cleanUp=suggested_profile.split(": ")
	accessList = cleanUp[1]
	listOfProfiles = accessList.split(", ")
	return listOfProfiles
	
def get_process_tree(profile):

	global casefolder
	global imagePath
	processTreeCommand = volatility + " -f " + imagePath + " --profile="+profile+" pstree > " + casefolder +"\\pstree.txt"
	output = subprocess.run(processTreeCommand, shell=True)



def get_netscan(profile):

	global casefolder
	getNetscanCommand = volatility + " -f " + imagePath + " --profile="+ profile +" netscan > " + casefolder +"\\netscan.txt"
	output = subprocess.run(getNetscanCommand, shell=True)

def get_cmdscan(profile):

	global casefolder
	getCMDscanCommand = volatility + " -f " + imagePath + " --profile="+ profile +" cmdline > " + casefolder +"\\cmdline.txt"
	output = subprocess.run(getCMDscanCommand, shell=True)

def get_processdump(profile):

	global casefolder
	os.mkdir(casefolder+ "\\exesample")
	getProcdumpCommand = volatility + " -f " + imagePath + " --profile="+ profile +" procdump -D "+ casefolder + "\\exesample > " + casefolder +"\\procdump.txt"
	output = subprocess.run(getProcdumpCommand, shell=True)
	src_dir = casefolder+ "\\exesample\\"
	for file in os.listdir(src_dir):
		if file[-4:] == ".exe":
			os.rename(src_dir+file, src_dir+file[:-4])
	with open(casefolder+'\\exe_hash.csv', 'w') as f:
		writer = csv.writer(f, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
		for directory, filename, path in recursive_file_listing(src_dir):
			writer.writerow((directory, filename,file_hash_hex(path, hashlib.md5),file_hash_hex(path, hashlib.sha1)))

def get_dlldump(profile):

	global casefolder
	os.mkdir(casefolder+ "\\dlls")
	getDllCommand = volatility + " -f " + imagePath + " --profile="+ profile +" dlldump -D " + casefolder + "\\dlls > " + casefolder +"\\dlldump.txt"
	output = subprocess.run(getDllCommand, shell=True)
	src_dir = casefolder+ "\\dlls\\"
	for file in os.listdir(src_dir):
		if file[-4:] == ".dll":
			os.rename(src_dir+file, src_dir+file[:-4])
	with open(casefolder+'\\dll_hash.csv', 'w') as f:
		writer = csv.writer(f, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
		for directory, filename, path in recursive_file_listing(src_dir):
			writer.writerow((directory, filename,file_hash_hex(path, hashlib.md5),file_hash_hex(path, hashlib.sha1)))

def getPublicIp():
	global casefolder
	with open(casefolder + '\\netscan.txt') as fh:
		fstring = fh.readlines() 
	# declaring the regex pattern for IP addresses 
	pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') 
	# initializing the list object 
	lst=[] 
	# extracting the IP addresses 
	for line in fstring:
		if pattern.search(line) is None:
			continue
		elif not ipaddress.IPv4Address(pattern.search(line)[0]).is_private:
			lst.append(pattern.search(line)[0])
	return lst

def getPrivateIp():
	"""Summary
	
	Returns:
	    TYPE: Description
	"""
	with open('netscan.txt') as fh:
		fstring = fh.readlines() 
	# declaring the regex pattern for IP addresses 
	pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') 
	# initializing the list object 
	lst=[] 
	# extracting the IP addresses 
	for line in fstring:
		if pattern.search(line) is None:
			continue
		elif ipaddress.IPv4Address(pattern.search(line)[0]).is_private:
			lst.append(pattern.search(line)[0])
	return lst

def ipWhoISLookUp(iplist):

	global casefolder
	f = open(casefolder + "\\whois.txt", "w")
	f.close()
	for ipAddr in iplist:
		if ipAddr == "0.0.0.0":
			pass
		else:
			for i in range(1,4):
				#Pick a random user agent
				user_agent = random.choice(user_agent_list)
				#Set the headers 
				headers = {'User-Agent': user_agent}
			r = requests.get("https://whatismyipaddress.com/ip/%s" %ipAddr, headers=headers)
			soup = BeautifulSoup(r.text, 'html.parser')
			text = soup.get_text()
			IPOutput = False
			for IP in text.splitlines():
				if "IP:" in IP:
					IPOutput = True
				if "Blacklist:" in IP:
					IPOutput = False

				if IPOutput is True:
					with open(casefolder+ "\\whois.txt", 'a') as ipInfoWrite:
						ipInfoWrite.write("%s\n"%IP)

			geoOutput = False
			for geoLine in text.splitlines():
				if "Continent:" in geoLine:
					geoOutput = True
				if "Geolocation Map" in geoLine:
					geoOutput = False
				if "Latitude:" in geoLine:
					geoOutput = False
				if "Longitude:" in geoLine:
					geoOutput = False
				if geoOutput is True:
					with open(casefolder+ "\\whois.txt", 'a') as ipGeoWrite:
						ipGeoWrite.write("%s\n"%geoLine)
			genGeoSeperator = open(casefolder + "\\whois.txt", "a")
			genGeoSeperator.write("\n")
			genGeoSeperator.close()



