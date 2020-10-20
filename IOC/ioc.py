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

currentDir = os.getcwd()
user_agent_list = [
	'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15',
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:77.0) Gecko/20100101 Firefox/77.0',
	'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36',
	'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:77.0) Gecko/20100101 Firefox/77.0',
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36',
]


volatility = currentDir+ "\\volatility_2.6_win64_standalone.exe"
vol = "volatility-2.6.standalone.exe"
imagePath = currentDir + "\\WIN7_FDS-20201017-090925.raw"

def file_hash_hex(file_path, hash_func):
	with open(file_path, 'rb') as f:
		return hash_func(f.read()).hexdigest()

def recursive_file_listing(base_dir):
	for directory, subdirs, files in os.walk(base_dir):
		for filename in files:
			yield directory, filename, os.path.join(directory, filename)

def cmdline(command):
	process = subprocess.Popen(
		args=command,
		stdout=subprocess.PIPE,
		stderr=subprocess.PIPE,
		shell=True
	)
	return process.communicate()[0]


def RAMimageInfo(path):
	imageInfoCommand = volatility + " -f " + path + " imageinfo > " + currentDir +"\\ImageInfo.txt"
	output = subprocess.run(imageInfoCommand, shell=True)
	#print(output)


def getProfile():
	with open('ImageInfo.txt') as f:
		suggested_profile = f.readline()
		f.close()
	suggested_profile = suggested_profile.rstrip()
	cleanUp=suggested_profile.split(": ")
	accessList = cleanUp[1]
	listOfProfiles = accessList.split(", ")
	return listOfProfiles
	
def getProcessTree(profile):
	processTreeCommand = volatility + " -f " + imagePath + " --profile="+ profile +" pstree > " + currentDir +"\\pstree.txt"
	output = subprocess.run(processTreeCommand, shell=True)

def getFilescan(profile):
	fileScanCommand = volatility + " -f " + imagePath + " --profile="+ profile +" filescan > " + currentDir +"\\filescan.txt"
	output = subprocess.run(fileScanCommand, shell=True)

def getNetscan(profile):
	getNetscanCommand = volatility + " -f " + imagePath + " --profile="+ profile +" netscan > " + currentDir +"\\netscan.txt"
	output = subprocess.run(getNetscanCommand, shell=True)

def getCmdscan(profile):
	getCMDscanCommand = volatility + " -f " + imagePath + " --profile="+ profile +" cmdline > " + currentDir +"\\cmdline.txt"
	output = subprocess.run(getCMDscanCommand, shell=True)

def getProcessDump(profile):
	getProcdumpCommand = volatility + " -f " + imagePath + " --profile="+ profile +" procdump -D .\\exesample > " + currentDir +"\\procdump.txt"
	output = subprocess.run(getProcdumpCommand, shell=True)
	src_dir = currentDir+ "\\exesample\\"
	for file in os.listdir(src_dir):
		if file[-4:] == ".exe":
			os.rename(src_dir+file, src_dir+file[:-4])
	with open('hash.csv', 'w') as f:
		writer = csv.writer(f, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
		for directory, filename, path in recursive_file_listing(src_dir):
			writer.writerow((directory, filename,file_hash_hex(path, hashlib.md5),file_hash_hex(path, hashlib.sha1)))

def get_dlldump(profile):
	getDllCommand = volatility + " -f " + imagePath + " --profile="+ profile +" dlldump -D .\\dlls > " + currentDir +"\\dlldump.txt"
	output = subprocess.run(getDllCommand, shell=True)

def getPublicIp():
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
		elif not ipaddress.IPv4Address(pattern.search(line)[0]).is_private:
			lst.append(pattern.search(line)[0])
	return lst

def getPrivateIp():
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
	f = open("whois.txt", "w")
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
					with open("whois.txt", 'a') as ipInfoWrite:
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
					with open("whois.txt", 'a') as ipGeoWrite:
						ipGeoWrite.write("%s\n"%geoLine)
			genGeoSeperator = open("whois.txt", "a")
			genGeoSeperator.write("\n")
			genGeoSeperator.close()




# ip = getPublicIp()
# for x in ip:
# 	print(x)
#ipWhoISLookUp(ip)


#RAMimageInfo(imagePath)
ProfileList = getProfile()
#print(ProfileList[0])
get_dlldump(ProfileList[0])
#getProcessDump(ProfileList[0])
#getCmdscan(ProfileList[0])


#getProcessTree(ProfileList[0])
#getNetscan(ProfileList[1])
#out(vol,imagePath)
#RAMimageInfo(imagePath)
# test = cmdline("dir")
# print(test)