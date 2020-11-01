# Enigma


##Software Requirements
* Python 3.8.6


     


##Installation
###Local
1. Ensure you have Mozila Firefox installed on your computer.

2. Ensure all dependencies are installed
`pip install -r requirements.txt`

3. ``


###Portable Method
1. Install Portable FireFox into the project folder where installer is downloadable at: <br>
https://portableapps.com/apps/internet/firefox_portable
2. Browse to `\FirefoxPortable\Other\Source` and copy `FirefoxPortable.ini` o the \FirefoxPortable folder. 
3. Modify the FirefoxPortable.ini file you copied and modify the following values

| Keys | Values |
| - | - |
| DisableSplashScreen | true |
| AllowMultipleInstances | true |

4. Copy your whole project into a USB drive. 
5. Start the toolkit by launching `launch.bat` from your drive/disk






Installation Guide

For VirusTotal: 
pip install virustotal-api

For Windows Security Event Log Toolkit:
pip install python-evtx



We have requested for an academic api key(which will expire in 6 months) with increased limits of request rates for this project as the normal api key does not have sufficient requests rates.

Normal key request rate
Per minute: 4
Per day: 1000
Per month: 30000

Academic key request rate
Per minute: 1000
Per day: 20000
Per month: 600000

These are the 3 possible results from VirusTotal <br>
Hash not found in database - VirusTotal Database does not have a record of this hash.<br>
Hash is not malicious - This hash is found in VirusTotal database and is not malicious. <br>
Hash is malicious - This hash is found in VirusTotal database and is malicious. <br>

