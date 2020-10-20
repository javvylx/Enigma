import virustotal3
from virus_total_apis import PublicApi as VirusTotalPublicApi
import csv

# Request rate = 4 per minute
# Daily quote = 1000 requests per day
# Monthly quota = 30000 requests per month
# api_key = "d265749382155a9250c2b1f2bc926eb6d7cfa0bd5c5ce00068225b516415cb67"
def virus_total(hashvalue):
    API_KEY = 'd265749382155a9250c2b1f2bc926eb6d7cfa0bd5c5ce00068225b516415cb67'
    vt = VirusTotalPublicApi(API_KEY)
    response = vt.get_file_report(hashvalue)
    return response

with open(r'C://Users//damie//Desktop//Y2T1//ICT2202_Digital_Forensics//Assignment//hash.csv') as hash_file:
    hash_csv = csv.reader(hash_file)
    file_name = []
    md5_hash = []
    sha1_hash = []
    # hash_ls = list(hash_csv)
    # print(hash_ls)
    for row in hash_csv:
        if (len(row) > 1):
            # file_path, file_name, md5_hash, sha1_hash = row
            file_path = row[0]
            file_name.append(row[1])
            md5_hash.append(row[2])
            md5_filtered = list(filter(lambda x: x != "", md5_hash))
            sha1_hash.append(row[3])
            sha1_filtered = list(filter(lambda x: x != "", sha1_hash))
    #print(md5_filtered)
    #print(sha1_filtered)
    try:
        results = virus_total(md5_filtered)['results']
        print(results)
        for p in range(len(results)):
            positives = results[p]['positives']
            total = results[p]['total']
            final_results = "{}/{}".format(positives, total)
    except KeyError:
        print("Index not found")
        exit(1)
    print("{}".format(final_results) + " positive signatures found.")






#hash_list = [line.rstrip('\n') for line in hash_file]

# for hash in hash_list:
#     print(hash)
#     response = vt.retrieve('2d75cc1bf8e57872781f9cd04a529256', raw=True, thing_type=hash)
#     print(response)


# vt = virustotal2.VirusTotal2("d265749382155a9250c2b1f2bc926eb6d7cfa0bd5c5ce00068225b516415cb67")
# mdl_content = urlopen("http://www.malwaredomainlist.com/updatescsv.php", "r")
# mdl_csv = csv.reader(mdl_content)
#
# for line in mdl_csv:
#     ip=line[2].split("/")[0]
#     try:
#         ip_report = vt.retrieve(ip)   #get the VT IP report for this IP
#     except:
#         print ("API error: on ip " + ip)
#
#     total_pos = sum([u["positives"] for u in ip_report.detected_urls])
#     total_scan = sum([u["total"] for u in ip_report.detected_urls])
#     count = len(ip_report.detected_urls)
#
#     print (str(count)+" URLs hosted on "+ip+" are called malicious by (on average) " + \
#           str(int(total_pos/count)) + " / " + str(int(total_scan/count)) + " scanners")