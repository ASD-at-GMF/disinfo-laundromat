import requests
import whois
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import socket
import time
import pandas as pd
import re
import sys
import ssl
from OpenSSL import crypto

visited = set()


def valid_url(url):
    # Regular expression for matching a URL
    regex = r"^(?:http|ftp)s?://"

    # If the URL does not match the regular expression
    if not re.match(regex, url):
        url = url.strip("/")
        # Add the 'http://' prefix to the URL
        url = "http://" + url
    if url == "http://":
        return ""

    return url

def get_domain_name(url):
    # Parse the URL using urlparse
    parsed_url = urlparse(url)

    # Get the domain name from the netloc attribute
    domain_name = parsed_url.netloc

    # Remove the www. prefix from the domain name
    if domain_name.startswith("www."):
        domain_name = domain_name[4:]

    return domain_name


def add_indicator(url, indicator_type, indicator_content):
    # Print the name and content attributes
    return {
        "indicator_type":indicator_type ,
        "indicator_content": indicator_content,  
        "domain_name": get_domain_name(url),
    }

def add_ip_address(domain_name):
    ip_indicators = []
    if domain_name.startswith("https://"):
        domain_name = domain_name[8:]

    try:
        # Resolve the domain name to an IP address
        ip_address = socket.gethostbyname(domain_name)
        ip_indicators.append(
            {
                "indicator_type": "ip",
                "indicator_content": ip_address,
                "domain_name": get_domain_name(domain_name),
            }
        )
        last_period_index = ip_address.rfind(".")
        subnet_id = ip_address[:last_period_index]
        ip_indicators.append(
            {
                "indicator_type": "subnet",
                "indicator_content": subnet_id,
                "domain_name": get_domain_name(domain_name),
            }
        )

        print(
            "The IP address of the domain name {} is {}".format(domain_name, ip_address)
        )
    except socket.gaierror:
        print("Could not resolve the domain name {}".format(domain_name))
    finally:
        return ip_indicators


def get_who_is(url):
    return whois.whois(url)


def add_who_is(url):
    whois_content = get_who_is(url)
    return {
        "indicator_type": "whois",
        "indicator_content": whois_content,
        "domain_name": get_domain_name(url),
    }


def parse_meta_tags(url, soup):

    meta_tags = soup.find_all("meta")
    tag_indicators = []
    # Iterate over the meta tags
    for meta_tag in meta_tags:
        # Get the name and content attributes of the meta tags
        name = meta_tag.get("name")
        content = meta_tag.get("content")
        if name and "verification" in name:
            tag_indicators.append(add_verification_tags(url, name, content))
        if name and name in ["twitter:site", "fb:pages" ]:
            tag_indicators.append(add_meta_social_tags(url, name, content))
        else:
            print(meta_tag)
    return tag_indicators


def add_verification_tags(url, name, content):

    # Print the name and content attributes
    return {
        "indicator_type": "verification_id",
        "indicator_content": name + "|" + content,  
        "domain_name": get_domain_name(url),
    }

def add_meta_social_tags(url, name, content):

    # Print the name and content attributes
    return {
        "indicator_type": "meta_social",
        "indicator_content": name + "|" + content,  
        "domain_name": get_domain_name(url),
    }

def parse_body(url, text):
    tag_indicators = []
    tag_indicators.extend(find_uuids(url,text))
    tag_indicators.extend(find_wallets(url,text))

    return tag_indicators

def find_with_regex(regex, text, url, indicator_type):
    tag_indicators = []
    matches = re.findall(regex,text)
    for match in matches:
        tag_indicators.append(add_indicator(url, indicator_type, match))
    return tag_indicators

def find_uuids(url, text):
    uuid_pattern = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    return find_with_regex(uuid_pattern,text, url, 'uuid')

def find_wallets(url, text):
    crypto_wallet_pattern = "(0x[a-fA-F0-9]{40}|[13][a-zA-Z0-9]{24,33}|[4][a-zA-Z0-9]{95}|[qp][a-zA-Z0-9]{25,34})"
    return find_with_regex(crypto_wallet_pattern, text, url, 'crypto-wallet')



def add_associated_domains_from_cert(url):
    print(url)
    port = 443    

    cert = ssl.get_server_certificate((get_domain_name(url), port))
    x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)

    sans = []
    for i in range(x509.get_extension_count()):
        ext = x509.get_extension(i)
        if ext.get_short_name() == b'subjectAltName':
            ext_val = ext.__str__()
            sans = ext_val.replace('DNS:','').split(',')

    tag_indicators = []
    tag_indicators.append(add_indicator(url, 'certificate', cert))
    for san in sans:
        tag_indicators.append(add_indicator(url, 'cert-domain', san))
    return tag_indicators

def crawl(url, visited_urls):
    indicators = []
    # Add the URL to the set of visited URLs
    visited_urls.add(get_domain_name(url))
    # Send a GET request to the specified URL
    response = requests.get(url)

    # Parse the HTML content of the page
    soup = BeautifulSoup(response.text, "html.parser")

    # Print the DOM
    print(url)
    indicators.extend(add_ip_address(url))
    indicators.append(add_who_is(url))
    indicators.extend(parse_meta_tags(url, soup))
    indicators.extend(parse_body(url, response.text))
    indicators.extend(add_associated_domains_from_cert(url))
    


    with open("soup.html", "w", encoding="utf-8", errors="ignore") as file:
        # Write the prettified HTML content to the file
        file.write(soup.prettify())

    # Find all the links in the page
    links = soup.find_all("a")
    for link in links:
        # Get the href attribute of the link
        href = link.get("href")

        # If the href attribute is not empty
        if href:
            href = valid_url(href)
            # If the URL has not been visited yet
            if get_domain_name(href) not in visited_urls and href != "":
                # Follow the link
                # time.sleep(1)
                try:
                    print(href)
                except Exception:
                    continue

    return indicators

if __name__ == "__main__":
    visited_urls = set()
    # Start the crawler at a specific URL
    indicators = crawl("https://www.rt.com", visited_urls)
    attribution_table = pd.DataFrame(
        columns=["indicator_type", "indicator_content", "domain_name"], data=indicators
    )
    print(attribution_table)
    if len(sys.argv) > 1:
        print(f"Assuming second arg {sys.argv[1]} is a filename")
        try:
            with open(sys.argv[1], "w") as f:
                attribution_table.to_csv(f)
        except Exception:
            print("oops!")
