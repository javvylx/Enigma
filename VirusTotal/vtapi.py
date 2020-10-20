import virustotal3
from virus_total_apis import PublicApi as VirusTotalPublicApi
import csv

# Request rate = 4 per minute
# Daily quote = 1000 requests per day
# Monthly quota = 30000 requests per month
# normal_api_key = "d265749382155a9250c2b1f2bc926eb6d7cfa0bd5c5ce00068225b516415cb67"

# Request rate = 1000 per minute
# Daily quote = 20000 requests per day
# Monthly quota = 600000 requests per month
# academic_api_key = 'dab678a43cd131a2ed0c91d0d26cc9aa3f2c69cee5198325bf4a1a29bf44c4f7'
def virus_total(hashvalue):
    API_KEY = 'dab678a43cd131a2ed0c91d0d26cc9aa3f2c69cee5198325bf4a1a29bf44c4f7'
    vt = VirusTotalPublicApi(API_KEY)
    response = vt.get_file_report(hashvalue)
    return response

with open(r'filepath') as hash_file:
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
    