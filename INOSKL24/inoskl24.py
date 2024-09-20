import whois
import requests
import socket
import ssl
from bs4 import BeautifulSoup
import sys
import nmap
from ipwhois import IPWhois


def banner():
    print("+=====================================================+")
    print("| ___ _   _  ___  ____  _  ___       _   ____  _  _   |")
    print("||_ _| \\ | |/ _ \\/ ___|| |/ / |     ( ) |___ \\| || |  |")
    print("| | ||  \\| | | | \\___ \\| ' /| |     |/    __) | || |_ |")
    print("| | || |\\  | |_| |___) | . \\| |___       / __/|__   _||")
    print("||___|_| \\_|\\___/|____/|_|\\_\\_____|     |_____|  |_|  |")
    print("+=====================================================+")

banner()

# Main function to gather domain information
def domain(domain_name):
    def get_domain_info(domain):
        try:
            w = whois.whois(domain)
            domain_info = {
                "Domain Name": w.domain_name,
                "Registrar": w.registrar,
                "Registrar URL": w.registrar_url,
                "Updated Date": w.updated_date,
                "Creation Date": w.creation_date,
                "Expiration Date": w.expiration_date,
                "Name Servers": ', '.join(w.name_servers) if w.name_servers else "N/A",
                "Organization": w.org,
                "State/Province": w.state,
                "Country": w.country,
                "Domain Status": w.status,
                "DNSSEC": w.dnssec
            }
            return domain_info
        except Exception as e:
            return {"Error": str(e)}

    def get_dns_info(domain):
        try:
            ip = socket.gethostbyname(domain)
            response = requests.get(f"https://ipinfo.io/{ip}/json")
            if response.status_code == 200:
                ip_info = response.json()
                return {
                    "IP Address": ip,
                    "Server Location": f"{ip_info.get('city', 'N/A')}, {ip_info.get('country', 'N/A')}",
                    "Server Provider": ip_info.get('org', 'N/A')
                }
            else:
                return {"IP Address": ip, "Server Location": "N/A"}
        except socket.gaierror:
            return {"Error": "Unable to resolve domain."}
        except requests.RequestException:
            return {"Error": "Failed to fetch DNS information."}

    def get_ssl_info(domain):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        "SSL Issuer": cert.get('issuer'),
                        "Valid From": cert.get('notBefore'),
                        "Valid To": cert.get('notAfter'),
                        "Common Name": cert.get('subject')
                    }
        except Exception as e:
            return {"Error": str(e)}

    def get_headers(domain_1):
        try:
            response = requests.get(f"http://{domain_1}")
            return dict(response.headers)
        except requests.RequestException as e:
            return {"Error": str(e)}

    def get_robots_txt(domain):
        try:
            response = requests.get(f"http://{domain}/robots.txt")
            if response.status_code == 200:
                return response.text.splitlines()  # Split lines into a list
            else:
                return ["No robots.txt found"]
        except requests.RequestException as e:
            return [f"Error: {str(e)}"]

    def get_linked_pages(domain):
        try:
            response = requests.get(f"http://{domain}")
            soup = BeautifulSoup(response.text, "html.parser")
            links = [link.get('href') for link in soup.find_all('a', href=True)]
            return links if links else ["No linked pages found."]
        except requests.RequestException as e:
            return [f"Error: {str(e)}"]

    def get_social_tags(domain):
        try:
            response = requests.get(f"http://{domain}")
            soup = BeautifulSoup(response.text, "html.parser")
            og_tags = {meta.get('property'): meta.get('content') for meta in soup.find_all('meta') if
                       'og:' in (meta.get('property') or '')}
            twitter_tags = {meta.get('name'): meta.get('content') for meta in soup.find_all('meta') if
                            'twitter:' in (meta.get('name') or '')}
            return {"OpenGraph Tags": og_tags, "Twitter Tags": twitter_tags}
        except requests.RequestException as e:
            return {"Error": str(e)}

    def get_server_status(domain):
        try:
            response = requests.get(f"http://{domain}")
            return {"HTTP Status Code": response.status_code}
        except requests.RequestException as e:
            return {"Error": str(e)}

    # Gathering all domain-related information
    domain_info = get_domain_info(domain_name)
    dns_info = get_dns_info(domain_name)
    ssl_info = get_ssl_info(domain_name)
    headers = get_headers(domain_name)
    robots_txt = get_robots_txt(domain_name)
    linked_pages = get_linked_pages(domain_name)
    social_tags = get_social_tags(domain_name)
    server_status = get_server_status(domain_name)

    # Aggregating all data into a single dictionary
    data = {**domain_info, **dns_info, **ssl_info, "Headers": headers,
            "Robots.txt": robots_txt, "Linked Pages": linked_pages,
            "Social Tags": social_tags, **server_status}

    return data

# New function to gather IP-related information
def ip_info(ip):
    # Geolocation using ipinfo.io API
    def get_geolocation(ip):
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json")
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    # Host/Port Discovery using nmap
    def get_host_port_info(ip):
        nm = nmap.PortScanner()
        nm.scan(ip, '1-1024')  # Scanning first 1024 ports
        return nm[ip]

    # BGP and IPv4 Info using ipwhois
    def get_ip_bgp_info(ip):
        obj = IPWhois(ip)
        return obj.lookup_whois()

    # Reputation using AbuseIPDB API
    def get_reputation(ip):
        api_key = 'YOUR_ABUSEIPDB_API_KEY'
        headers = {
            'Key': api_key,
            'Accept': 'application/json'
        }
        response = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}", headers=headers)
        return response.json()

    # Neighbor Domains using viewdns.info API
    def get_neighbor_domains(ip):
        response = requests.get(f"https://viewdns.info/reverseip/?host={ip}&t=1")
        return response.text

    # Wireless Network Info (local wireless information)
    def get_wireless_info():
        return {"SSID": "ExampleNetwork", "Signal": "Strong", "Channel": 6}  # Placeholder

    # Gather all information
    results = {
        "geolocation": get_geolocation(ip),
        "host_port_info": get_host_port_info(ip),
        "bgp_info": get_ip_bgp_info(ip),
        "reputation": get_reputation(ip),
        "neighbor_domains": get_neighbor_domains(ip),
        "wireless_info": get_wireless_info(),
    }

    return results

# Print the data to CLI
def print_cli_report(data):
    for key, value in data.items():
        if isinstance(value, dict):
            print(f"\n{key}:")
            for sub_key, sub_value in value.items():
                print(f"  {sub_key}: {sub_value}")
        elif isinstance(value, list):
            print(f"\n{key}:")
            for item in value:
                print(f"  - {item}")
        else:
            print(f"\n{key}: {value}")


def main():
    try:
        target = input("Enter a domain or IP address: ").strip()

        # Check if input is IP or domain
        try:
            socket.inet_aton(target)
            is_ip = True
        except socket.error:
            is_ip = False

        if is_ip:
            data = ip_info(target)
        else:
            data = domain(target)

        print_cli_report(data)

    except KeyboardInterrupt:
        print("\nProcess interrupted by user.")
        sys.exit(1)


if __name__ == "__main__":
    main()
