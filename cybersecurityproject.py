import argparse
import requests
import json
import sys
import base64

class CyberProject():
    '''Gathers STIX2 from data sources such as Zeus, X-force Threat Exchange, Ransomware, Threatexpert, FeodoIP Blocklist'''

    def __init__(self):
        '''
        constructor
        '''
        self.url = 'https://api.xforce.ibmcloud.com:443'

    def parse_command_line_arguments(self, args):
        '''
        Argument Parser
        :param args:
        :return:
        '''
        parser = argparse.ArgumentParser()
        parser.add_argument('--search', help='Query any items(virus/malware etc)')
        parser.add_argument('--hash', help = 'Get Malware for file hash')
        parser.add_argument('--ip', help = 'Get IP by category')
        parser.add_argument('--whois', help = 'Get who is information')
        parser.add_argument('--iprep', help = 'Get IP reputation')
        parser.add_argument('--vulninfo', help = 'Search Vulnerability Information')
        parser.add_argument('--latestvuln', action = 'store_true', help = 'Get Recent Vulnerability Information')
        parser.add_argument('--cve', help = 'Get information based on cve')
        parser.add_argument('--urlmalware', help = 'Returns the malware associated with the entered URL')
        parser.add_argument('--dnsinfo', help = 'Get DNS Records for IP' )
        return parser.parse_args(args)

    def base_url(self):
        '''using ibm x-force api '''
        url = 'https://api.xforce.ibmcloud.com/'
        return url


    def write_to_file(self, data):
        '''
        Write Json data to a file
        '''
        try:
            with open('data.json', 'w') as output_file:
                data = json.dump(data, output_file)
                return data

        except Exception as err:
            print("%s ", err)

    def search_items(self, headers, parsed_args):
        '''
        Search for the malware, virus, phishing etc
        :return:
        '''
        get_search_items_for_type = '{}/casefiles/public/fulltext?q={}'.format(self.url, parsed_args.search)
        stix_data_get_items = requests.get(get_search_items_for_type)
        stix_search_data = self.send_request(stix_data_get_items,headers)
        print(stix_search_data)
        self.write_to_file(stix_search_data)

    def get_info_for_hash(self, parsed_args, headers):
        '''
        Get the Malware information for the hash specified
        :param parsed_args:
        :return:
        '''
        get_malware_info_for_hash_for_url = '{}/malware/{}'.format(self.url, parsed_args.hash)
        get_malware_info_stix_data = self.send_request(get_malware_info_for_hash_for_url,headers)
        print(get_malware_info_stix_data)
        self.write_to_file(get_malware_info_stix_data)

    def get_info_for_ip(self, parsed_args, headers):
        '''
        Get information about the ip address provided
        :param parsed_args:
        :return:
        '''
        get_ip_information_for_url = '{}/ipr/{}'.format(self.url, parsed_args.ip)
        get_information =  self.send_request(get_ip_information_for_url,headers)
        print(get_information)
        self.write_to_file(get_information)


    def get_info_for_who_is(self, parsed_args, headers):
        '''
        Get who is information for the IP address
        :param parsed_args:
        :param headers:
        :return:
        '''
        get_who_is_information_for_url = '{}/whois/{}'.format(self.url, parsed_args.whois)
        get_information_for_who_is = self.send_request(get_who_is_information_for_url, headers)
        print(get_information_for_who_is)
        self.write_to_file(get_information_for_who_is)


    def get_info_for_ip_reputation(self, parsed_args, headers):
        '''
        Get IP reputation
        :param parsed_args:
        :param headers:
        :return:
        '''
        ip_reputation_url = '{}/ipr/history/{}'.format(self.url, parsed_args.iprep)
        get_ip_information = self.send_request(ip_reputation_url, headers)
        print(get_ip_information)
        self.write_to_file(get_ip_information)

    def get_vulnerability_information(self, parsed_args, headers):
        '''Get Vulnerability information when the name of vulnerability(string) is passed'''

        get_vulnerability_info_from_url = '{}/vulnerabilities/fulltext?q={}'.format(self.url, parsed_args.vulninfo)
        get_information = self.send_request(get_vulnerability_info_from_url, headers)
        print(get_information)
        self.write_to_file(get_information)

    def get_recent_vulnerability_information(self, headers):
        '''
        Get the Latest Vulnerabiility feed
        '''
        get_latest_vuln_feed_from_url = '{}/vulnerabilities/'.format(self.url)
        get_information = self.send_request(get_latest_vuln_feed_from_url, headers)
        print(get_information)
        self.write_to_file(get_information)

    def get_vulnerability_information_based_on_cve_number(self, parsed_args, headers):
        '''Get Vulnerability information based on the CVE numnber
        eg :CVE-2014-2601'''
        get_cve_info_from_url = '{}/vulnerabilities/search/{}'.format(self.url, parsed_args.cve)
        get_information_for_cve = self.send_request(get_cve_info_from_url, headers)
        print(get_information_for_cve)
        self.write_to_file(get_information_for_cve)

    def get_dns_records_based_on_ip(self, parsed_args, headers):
        '''
        Get Domain Name Server Records from X-force for an IP
        :param parsed_args:
        :param headers:
        :return:
        '''
        get_dns_from_url = '{}/resolve/{}'.format(self.url, parsed_args.dnsinfo)
        get_dns_information = self.send_request(get_dns_from_url, headers)
        print(get_dns_information)
        self.write_to_file(get_dns_information)

    def get_url_malware_information(self, parsed_args, headers):
        '''Get URL Malware information based on the website name'''
        get_url = '{}/url/malware/{}'.format(self.url, parsed_args.urlmalware)
        get_malware_info_for_url = self.send_request(get_url, headers)
        print(get_malware_info_for_url)
        self.write_to_file(get_malware_info_for_url)

    def send_request(self, apiurl, headers):
        fullurl = apiurl
        response = requests.get(fullurl, params='', headers=headers, timeout=20)
        all_json = response.json()
        data= json.dumps(all_json, indent=4, sort_keys=True)
        return data

    def main(self, args):

        try:

            parsed_args = self.parse_command_line_arguments(args)
            # X-Force API Key and Password
            key = " "
            password = " "

            token = base64.b64encode(key + ":" + password)
            headers = {'Authorization': "Basic " + token, 'Accept': 'application/json'}

            if parsed_args.search:
                self.search_items(headers, parsed_args)
            elif parsed_args.hash:
                self.get_info_for_hash(parsed_args, headers)
            elif parsed_args.ip:
                self.get_info_for_ip(parsed_args, headers)
            elif parsed_args.whois:
                self.get_info_for_who_is(parsed_args, headers)
            elif parsed_args.iprep:
                self.get_info_for_ip_reputation(parsed_args, headers)
            elif parsed_args.vulninfo:
                self.get_vulnerability_information(parsed_args, headers)
            elif parsed_args.latestvuln:
                self.get_recent_vulnerability_information(headers)
            elif parsed_args.cve:
                self.get_vulnerability_information_based_on_cve_number(parsed_args, headers)
            elif parsed_args.urlmalware:
                self.get_url_malware_information(parsed_args, headers)
            elif parsed_args.dnsinfo:
                self.get_dns_records_based_on_ip(parsed_args, headers)

        except Exception as err:
            print ("Error : %s ", err)

if __name__ == "__main__":
    security_project = CyberProject()
    security_project.main(sys.argv[1:])
