from datetime import datetime
import requests
import dns
import dns.resolver
import socket

class NetworkScanner:
    def __init__(self):
        pass

    def check_domain_status(self, domain):
        try:
            response = None
            try:
                response = requests.get(url=f"https://www.{domain}", headers={}, data="")
            except Exception as e:
                response = requests.get(url=f"https://{domain}", headers={}, data="")
            return True if response.status_code == 200 else False
        except Exception as e:
            print(str(e))
            return False

    def get_ip_addresses(self, domain):
        ipv4, ipv6 = None, None
        try:
            response = requests.get(f"https://dns.google.com/resolve?name={domain}&type=A")
            ipv4_info = response.json()
            if ipv4_info["Answer"] is not None:
                ipv4 = ipv4_info["Answer"][0]["data"]
            response = requests.get(f"https://dns.google.com/resolve?name={domain}&type=AAAA")
            ipv6_info = response.json()
            if ipv6_info and ipv6_info.get("Answer"):
                ipv6= ipv6_info["Answer"][0]["data"]
            return [ipv4,ipv6]
        except Exception as e:
            return

    def get_dns_records(self, domain):
        record_list = []
        try:
            dns_record_types = [dns.rdatatype.CNAME, dns.rdatatype.A,dns.rdatatype.AAAA,dns.rdatatype.MX,dns.rdatatype.NS,dns.rdatatype.SOA,dns.rdatatype.PTR,dns.rdatatype.SRV]
            for dns_record_type in dns_record_types:
                try:
                    data = dns.resolver.resolve(qname=domain, rdtype=dns_record_type).response
                    data = str(data)
                    start_index = data.rfind("IN") + 3
                    data = data[start_index:].split(";")[0]
                    data = data[:len(data)-2].split(' ')
                    record_list.append(f"{data[0]} - {data[len(data) - 1]}")
                except Exception as e:
                    pass
        except Exception as e:
            pass
        return record_list

    def get_open_ports(self, domain):
        open_ports = []
        try:
            for port in range(1,1024):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.4)
                    resp = s.connect_ex((domain, port))
                    if resp == 0:
                        open_ports.append(f"{port}/{socket.getservbyport(port, 'tcp')}")
                except Exception as e:
                    pass
        except Exception as e:
            print(str(e))

        return open_ports

    def start_scan(self, domain):
        print('-' * 60)
        if self.check_domain_status(domain=domain):
            print(f"\nScan results for {domain}")
            start_time = datetime.now()
            ip_addresses = self.get_ip_addresses(domain)
            print(f"\tIP Addresses:\n\t\tIPv4 Address/A Records: {ip_addresses[0]}")
            print(f"\t\tIPv6 Address/AAAA Records: {ip_addresses[1]}\n")
            print("\tDNS Records:")
            for record in self.get_dns_records(domain=domain):
                print(f"\t\t{record}")
            print("\n\tOpen ports and protocols:")
            for port in self.get_open_ports(domain=domain):
                print(f"\t\t{port}")
            end_time = datetime.now()
            print(f"\n\tTotal time spent while scanning: {end_time-start_time}\n")
        else:
            print("Domain is unreachable")
        print('-' * 60)

def main():
    scanner = NetworkScanner()
    domain = input("Enter a domain to start scanning!\n")
    scanner.start_scan(domain=domain)

if __name__ == '__main__':
    main()
