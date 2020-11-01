# Enigma

Pre-requisites:
Python 3.x or newer

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
Hash not found in database - VirusTotal Database does not have a record of this hash.
Hash is not malicious - This hash is found in VirusTotal database and is not malicious.
Hash is malicious - This hash is found in VirusTotal database and is malicious.

