import requests
import whois
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import socket
import time
import pandas as pd
import re

visited = set()

attribution_table = pd.DataFrame(["indicator_type","indicator_content","domain_name"])


def valid_url(url):
    # Regular expression for matching a URL
    regex = r'^(?:http|ftp)s?://'

    # If the URL does not match the regular expression
    if not re.match(regex, url):
        url = url.strip("/")
        # Add the 'http://' prefix to the URL
        url = 'http://' + url
    if url == 'http://':
        return ""

    return url


def get_uuids(soup):
    regex = r'[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}'

    # If the URL does not match the regular expression
    if not re.match(regex, url):
        url = url.strip("/")
        # Add the 'http://' prefix to the URL
        url = 'http://' + url
    if url == 'http://':
        return ""

    return url


def get_domain_name(url):
    # Parse the URL using urlparse
    parsed_url = urlparse(url)

    # Get the domain name from the netloc attribute
    domain_name = parsed_url.netloc

    # Remove the www. prefix from the domain name
    if domain_name.startswith('www.'):
        domain_name = domain_name[4:]

    return domain_name


def add_ip_address(domain_name):

    if domain_name.startswith('https://'):
        domain_name = domain_name[8:]

    try:
        # Resolve the domain name to an IP address
        ip_address = socket.gethostbyname(domain_name)
        attribution_table = attribution_table.append({'indicator_type': 'ip', 'indicator_content': ip_address, 'domain_name': get_domain_name(domain_name) }, ignore_index=True)
        last_period_index = ip_address.rfind('.')
        subnet_id = ip_address[:last_period_index]
        attribution_table = attribution_table.append({'indicator_type': 'subnet', 'indicator_content': subnet_id, 'domain_name': get_domain_name(domain_name) }, ignore_index=True)

        print("The IP address of the domain name {} is {}".format(
            domain_name, ip_address))
    except socket.gaierror:
        print("Could not resolve the domain name {}".format(domain_name))


def get_who_is(url):
    return whois.whois(url)


def add_who_is(url, whois):
    if 'Private' not in whois.name:
        attribution_table = attribution_table.append({'indicator_type': 'whois', 'indicator_content': whois, 'domain_name': get_domain_name(url) }, ignore_index=True)


def parse_meta_tags(url, soup):

    meta_tags = soup.find_all('meta')

    # Iterate over the meta tags
    for meta_tag in meta_tags:
        # Get the name and content attributes of the meta tags
        name = meta_tag.get('name')
        content = meta_tag.get('content')
        if name and 'verification' in name:
            add_verification_tags(url, name, content)
        else:
            print(meta_tag)


def add_verification_tags(url, name, content):

    # Print the name and content attributes
    attribution_table = attribution_table.append({'indicator_type': 'verification_id', 'indicator_content':  name + '|' + content, 'domain_name': get_domain_name(url) }, ignore_index=True)


def crawl(url, visited_urls):
    # Add the URL to the set of visited URLs
    visited_urls.add(get_domain_name(url))
    # Send a GET request to the specified URL
    response = requests.get(url)

    # Parse the HTML content of the page
    soup = BeautifulSoup(response.text, 'html.parser')

    # Print the DOM
    print(url)
    add_ip_address(url)
    whoisResults = get_who_is(url)
    add_who_is(url, whoisResults)
    parse_meta_tags(url, soup)

    with open('soup.html', 'w', encoding='utf-8', errors='ignore') as file:
        # Write the prettified HTML content to the file
        file.write(soup.prettify())

    # Find all the links in the page
    links = soup.find_all('a')
    for link in links:
        # Get the href attribute of the link
        href = link.get('href')

        # If the href attribute is not empty
        if href:
            href = valid_url(href)
            # If the URL has not been visited yet
            if get_domain_name(href) not in visited_urls and href != "":
                # Follow the link
                #time.sleep(1)
                try:
                    print(href)
                except Exception:
                    continue


visited_urls = set()
# Start the crawler at a specific URL
crawl('https://www.rt.com', visited_urls)
print(attribution_table)
