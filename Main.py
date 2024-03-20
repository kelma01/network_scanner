from datetime import datetime
import requests
import dns
import dns.resolver
import socket
from sslyze import *


class NetworkScanner:
    def __init__(self):
        self.domain = None

    def check_domain_status(self):
        try:
            response = None
            try:
                response = requests.get(url=f"https://www.{self.domain}", headers={}, data="")
            except Exception as e:
                response = requests.get(url=f"https://{self.domain}", headers={}, data="")
            return True if response.status_code == 200 else False
        except Exception as e:
            print(str(e))
            return False

    def get_ip_addresses(self):
        ipv4, ipv6 = None, None
        try:
            response = requests.get(f"https://dns.google.com/resolve?name={self.domain}&type=A")
            ipv4_info = response.json()
            if ipv4_info["Answer"] is not None:
                ipv4 = ipv4_info["Answer"][0]["data"]
            response = requests.get(f"https://dns.google.com/resolve?name={self.domain}&type=AAAA")
            ipv6_info = response.json()
            if ipv6_info and ipv6_info.get("Answer"):
                ipv6 = ipv6_info["Answer"][0]["data"]
            return [ipv4, ipv6]
        except Exception as e:
            return

    def get_dns_records(self):
        record_list = []
        try:
            dns_record_types = [dns.rdatatype.CNAME, dns.rdatatype.A, dns.rdatatype.AAAA, dns.rdatatype.MX,
                                dns.rdatatype.NS, dns.rdatatype.SOA, dns.rdatatype.PTR, dns.rdatatype.SRV]
            for dns_record_type in dns_record_types:
                try:
                    data = dns.resolver.resolve(qname=self.domain, rdtype=dns_record_type).response
                    data = str(data)
                    start_index = data.rfind("IN") + 3
                    data = data[start_index:].split(";")[0]
                    data = data[:len(data) - 2].split(' ')
                    record_list.append(f"{data[0]} - {data[len(data) - 1]}")
                except Exception as e:
                    pass
        except Exception as e:
            pass
        return record_list

    def get_open_ports(self):
        open_ports = []
        try:
            for port in range(1, 1024):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.4)
                    resp = s.connect_ex((self.domain, port))
                    if resp == 0:
                        open_ports.append(f"{port}/{socket.getservbyport(port, 'tcp')}")
                except Exception as e:
                    pass
        except Exception as e:
            print(str(e))

        return open_ports

    def get_whois_info_from_web(self):
        try:
            target_url = f'https://rwhois.he.net/whois.php?query={self.domain}'
            resp = requests.get(url=target_url)
            info = resp.text
            info = info[info.find('Domain Name: '):info.find('URL of the') - 1].split('\n')
            info[0] = f"   {info[0]}"
            return info
        except Exception as e:
            print(str(e))

    def get_subdomains(self):
        results = []
        with open('subdomain_list.txt', 'r') as f:
            subdomains = f.read().splitlines()
            for subdomain in subdomains:
                try:
                    if requests.get(url=f"https://{subdomain}.{self.domain}", timeout=2).status_code == 200:
                        results.append(subdomain)
                    else:
                        pass
                except Exception as e:
                    pass
        return results

    def sslyze_scanner(self):   #there are so many results that not returning with this function, edit this function according to the output you want.
        scanner = Scanner()
        scanner.queue_scans([ServerScanRequest(server_location=ServerNetworkLocation(hostname=self.domain))])
        try:
            for result in scanner.get_results():
                if result.connectivity_status == ServerConnectivityStatusEnum.ERROR:
                    raise Exception
                not_valid_after = result.scan_result.certificate_info.result.certificate_deployments[0].received_certificate_chain[0].not_valid_after
                validity_status = True if not_valid_after > datetime.today() else False
                supported_cipher_suite = result.connectivity_result.cipher_suite_supported
                return not_valid_after, validity_status, supported_cipher_suite
        except Exception as e:
            print("SSL Scan Failed")


    def start_scan(self):
        print('-' * 60)
        if self.check_domain_status():
            print(f"\nScan results for {self.domain}")
            start_time = datetime.now()

            ip_addresses = self.get_ip_addresses()
            print(f"\tIP Addresses:\n\t\tIPv4 Address/A Records: {ip_addresses[0]}")
            print(f"\t\tIPv6 Address/AAAA Records: {ip_addresses[1]}\n")

            print("\tDNS Records:")
            for record in self.get_dns_records():
                print(f"\t\t{record}")

            print("\n\tWHOIS Information:")
            for info in self.get_whois_info_from_web():
                print(f"\t{info}")

            print("\tSubdomains:")
            for result in self.get_subdomains():
                print(f"\t\t{result}.{self.domain}")

            print("\tOpen Ports and Protocols:")
            for port in self.get_open_ports():
                print(f"\t\t{port}")

            print("\tSSL Scan Results:")
            not_valid_after, validity_status, supported_cipher_suite = self.sslyze_scanner()
            print(f"\t\tCertificate is not valid after: {not_valid_after}")
            print(f"\t\tCertificate validity status: {validity_status}")
            print(f"\t\tSupported cipher suite: {supported_cipher_suite}")


            end_time = datetime.now()
            print(f"\n\tTotal time spent while scanning: {end_time - start_time}\n")
        else:
            print("Domain is unreachable")
        print('-' * 60)


def main():
    scanner = NetworkScanner()
    scanner.domain = input("Enter a domain to start scanning!\n")
    scanner.start_scan()


if __name__ == '__main__':
    main()
