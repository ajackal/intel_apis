import json
import csv
import urllib
import os
import errno


url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'


def create_dir(r_name):
    pwd = os.getcwd()
    wk_dir = os.path.join(pwd, r_name)

    try:
        os.mkdir(wk_dir)
        os.chdir(wk_dir)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise


def api_call(tgt, key, r_json):
    parameters = {'ip': str(tgt), 'apikey': key}

    try:
        response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
        response_dict = json.loads(response)
        with open(r_json, 'w') as r:
            json.dump(response_dict, r)
    except Exception as e:
        print "[!] Error conducting API call: {0}".format(e)
        exit(0)


def parse_json(r_json):
    r = open(r_json, 'r')
    data = r.read()

    global parsed
    parsed = json.loads(data)


def extract_urls(r_txt):
    d_urls = parsed["detected_urls"]

    with open(r_txt, 'w') as u:
        x = 0
        for d_url in d_urls:
            u.write(parsed["detected_urls"][x]["url"] + "\n")
            x += 1


def create_csv(r_csv):
    d_urls = parsed["detected_urls"]

    with open(r_csv, 'w') as c:
        csvwriter = csv.writer(c)
        count = 0
        for d_url in d_urls:
            if count == 0:
                header = d_url.keys()
                csvwriter.writerow(header)
                count += 1
            csvwriter.writerow(d_url.values())


def main():
    k = open('treasure.txt', 'r')
    key = k.readline()
    tgt = raw_input("tgt ip: ")
    r_name = "report_" + tgt
    r_json = r_name + ".json"
    r_txt = r_name + ".txt"
    r_csv = "csv_" + r_name + ".csv"

    create_dir(r_name)
    api_call(tgt, key, r_json)
    parse_json(r_json)
    extract_urls(r_txt)
    create_csv(r_csv)


if __name__ == "__main__":
    main()
