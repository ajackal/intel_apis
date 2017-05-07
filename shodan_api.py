#! /usr/bin/env python

import shodan
import optparse
# future support for json formatting
# import json
import time

# global list IPs to search for; generated from input file
querys = []

# defines headers for the csv output file
headers = False


# reads api_key from file defined with '-k'
def api_key_read(api_key):
    k = open(api_key, 'r')
    key = k.readline()
    api = shodan.Shodan(key)
    return api


# reads IP address from file defined with '-i'
# one address per line in the file
def ip_read_file(ifile):
    with open(ifile, 'r') as i:
        for line in i.readlines():
            a = line.strip('\n')
            querys.append(a)


# makes the call to shodan and outputs to file if defined with '-o'
def shodan_call(api, ofile):
    # for each IP address make a query...
    for query in querys:
        try:
            # actual API call
            results = api.host(query)
            # print results if there are any
            if results is not None:
                print '[#] Results found for % s' % results['ip_str']
            else:
                print '[!] No results found for %s' % results['ip_str']
            # if an output file is defined, call the write_csv function
            if ofile is not None:
                write_csv(results, ofile, headers)
            # if no output file is defined, write to stdout; ignore 'data' section
            else:
                for x in results:
                    if x == 'data':
                        continue
                    else:
                        print x, results[x]
        # catch any errors running the API
        except shodan.APIError, e:
            print '[!] Error: {0} >> {1}'.format(e, query)
            # if the error is limit, sleep function for 60 seconds
            if "Request limit reached" in e:
                time.sleep(60)


# writes the results to csv if output file is defined with '-o'
def write_csv(results, ofile, headers):
    # TODO: add try and create new file if file is locked/exists
    # opens file as an append
    with open(ofile, 'a+') as c:
        # writes the headers to the file
        # TODO: add class to format the results to the header is effective
        if headers is False:
            # writes keys as the headers of the csv
            for key in results.keys():
                # skip data again
                if key == "data":
                    continue
                else:
                    c.write(str(key) + ",")
            c.write("\n")
            headers = True
        for x in results:
            if x == 'data':
                # delete comments to create a html file with the data dump
                # still debating how useful this will be
                # ofileHTML = results['ip_str'] + '_data.html'
                # with open(ofileHTML, 'w') as h:
                # h.write(str(results['data']))
                # continue
                continue
            else:
                # writes the value of each key to one line (for each host)
                c.write(str(results[x]) + ",")
        # creates new line for the next host
        c.write("\n")


def main():
    # parser options
    parser = optparse.OptionParser("usage: shodan_api.py -k <api key> -i <input file> -o <output file>")
    parser.add_option('-k', dest='api_key', type='string', help='read api key from this file')
    parser.add_option('-i', dest='ifile', type='string', help='input file to read')
    parser.add_option('-o', dest='ofile', type='string', help='write to this output file <optional>')
    (options, args) = parser.parse_args()

    if options.ifile is None or options.api_key is None:
        print parser.usage
        exit(0)
    else:
        api_key = options.api_key
        ifile = options.ifile
        ofile = options.ofile
        api = api_key_read(api_key)
        ip_read_file(ifile)
        shodan_call(api, ofile)


if __name__ == "__main__":
    main()
