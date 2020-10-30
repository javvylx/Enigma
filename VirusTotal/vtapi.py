from virus_total_apis import PrivateApi as VirusTotalPrivateApi
import csv
import json
import time


file_name = []
md5_hash = []
sha1_hash = []
malicious_hash = []
non_malicious_hash = []
not_in_VT = []

# Request rate = 4 per minute
# Daily quota = 1000 requests per day
# Monthly quota = 30000 requests per month
# normal_api_key = 'd265749382155a9250c2b1f2bc926eb6d7cfa0bd5c5ce00068225b516415cb67'

# Request rate = 1000 per minute
# Daily quota = 20000 requests per day
# Monthly quota = 600000 requests per month
# academic_api_key = 'dab678a43cd131a2ed0c91d0d26cc9aa3f2c69cee5198325bf4a1a29bf44c4f7'
def virus_total(hash):
    API_KEY = 'dab678a43cd131a2ed0c91d0d26cc9aa3f2c69cee5198325bf4a1a29bf44c4f7'
    vt = VirusTotalPrivateApi(API_KEY)
    response = vt.get_file_report(hash, allinfo=1)
    return response

def get_file_report(resource):
    try:
        for hash in resource:
            results = virus_total(hash)
            response = int(results.get('response_code'))
            # print(results)
            if response == 0:
                print(hash + ' cannot be found in VirusTotal Database\n')
                not_in_VT.append(hash)
            elif response == 1:
                positiveHits = int(results.get('positives'))
                totalHits = int(results.get('total'))
                if positiveHits == 0:
                    print(hash + ' is not malicious\n')
                    non_malicious_hash.append(hash)
                else:
                    final_results = "{}/{}".format(positiveHits, totalHits)
                    print(hash + ' is malicious. Hit count: ' + '{}'.format(final_results) +
                          ' positive signatures found.\n')
                    malicious_hash.append(hash)
            # time.sleep(2)
        print("These hashes are not found in VirusTotal database: " + str(not_in_VT) + '\n')
        print("These hashes are not malicious: " + str(non_malicious_hash) + '\n')
        print("These hashes are malicious: " + str(malicious_hash) + '\n')
    except KeyError:
        print('Index not found')
        exit(1)

def _filter_resource_in_csv():
    with open(r'C://Users//damie//Desktop//Y2T1//ICT2202_Digital_Forensics//Assignment//exe_hash.csv') as hash_file:
        hash_csv = csv.reader(hash_file)
        for row in hash_csv:
            if (len(row) > 1):
                # file_path, file_name, md5_hash, sha1_hash = row
                file_path = row[0]
                file_name.append(row[1])
                md5_hash.append(row[2])
                md5_filtered = list(filter(lambda x: x != "", md5_hash))
                sha1_hash.append(row[3])
                sha1_filtered = list(filter(lambda x: x != "", sha1_hash))
    return md5_filtered

def main():
    get_hash = _filter_resource_in_csv()
    get_file_report(get_hash)


if __name__ == "__main__":
    main()