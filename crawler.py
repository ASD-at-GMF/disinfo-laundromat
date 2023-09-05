import os
import requests
import whois
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urlsplit
import socket
from urllib.error import HTTPError
import time
import pandas as pd
import re
from io import BytesIO
import argparse
import ssl
from OpenSSL import crypto
import traceback
import yaml
import json
import tldextract
import imagehash
import subprocess
import blockcypher
from PIL import Image
from pathlib import Path
from typing import List, Dict, Set
from usp.tree import sitemap_tree_for_homepage
import feedparser


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


def add_response_headers(url, soup, response):
    header_indicators = []
    for header,value in response.headers.items():
        try:
            if header.startswith('Server'):
                header_indicators.append(add_indicator(url, '3-header-server', value))
            if (header.startswith('X-') or header.startswith('x-')) and header.lower() not in ['x-content-type-options', 'x-frame-options', 'x-xss-protection', 'x-request-id', 'x-ua-compatible', 'x-permitted-cross-domain-policies', 'x-dns-prefetch-control', 'x-robots-tag']:
                header_indicators.append(add_indicator(url, '3-header-nonstd-value', header + ':' + value))
        except Exception as e:
            print(e.message)
    return header_indicators

def add_indicator(url, indicator_type, indicator_content):
    # Print the name and content attributes
    return {
        "indicator_type": indicator_type,
        "indicator_content": indicator_content,
        "domain_name": get_domain_name(url),
    }


def add_ip_address(domain_name, soup, response):
    ip_indicators = []
    if domain_name.startswith("https://"):
        host_name = domain_name[8:]
    else:
        host_name = domain_name

    try:
        # Resolve the domain name to an IP address
        ip_address = socket.gethostbyname(host_name)
        ip_indicators.append(add_indicator(domain, "1-ip", ip_address))

        last_period_index = ip_address.rfind(".")
        subnet_id = ip_address[:last_period_index]
        ip_indicators.append(add_indicator(domain, "2-subnet", subnet_id))
    except socket.gaierror:
        print("Could not resolve the domain name {}".format(domain_name))
    finally:
        return ip_indicators

def add_who_is(url, soup, response):
    whois_indicators = []
    try:
        result = whois.whois(url)
        if result.text != 'Socket not responding: [Errno 11001] getaddrinfo failed':
            whois_indicators.append(add_indicator(url, "3-whois-registrar", result.registrar ))
            whois_indicators.append(add_indicator(url, "3-whois_server", result.whois_server ))
            whois_indicators.append(add_indicator(url, "3-whois_creation_date", result.creation_date ))
            if 'name' in result and result.name is not None and isinstance(result.name, list):
                if 'priva' not in result.name.lower() and 'proxy' not in result.name.lower() and 'guard' not in result.name.lower() and 'protect' not in result.name.lower() and 'mask' not in result.name.lower()  and 'secur' not in result.name.lower():
                    whois_indicators.append(add_indicator(url, "1-whois_emails", result.emails ))
                    whois_indicators.append(add_indicator(url, "1-whois_name", result.name ))
                    whois_indicators.append(add_indicator(url, "1-whois_org", result.org ))
                    whois_indicators.append(add_indicator(url, "1-whois_address", result.address ))
                    whois_indicators.append(add_indicator(url, "2-whois_citystatecountry", result.city + ', '+ result.state + ', '+ result.country))
    except Exception as e:
        print(e.message)
    return whois_indicators
    
def get_tracert(ip_address):
    tracert = subprocess.Popen(['tracert', ip_address], stdout=subprocess.PIPE)
    output, _ = tracert.communicate()
    return output.decode().strip().split('\n')

def parse_classes(url, soup, response):
    tag_indicators = []
    used_classes = set()
    for elem in soup.select("[class]"):
        classes = elem["class"]
        used_classes.update(classes)
    tag_indicators.append(add_indicator(url, "3-css-classes", ",".join(used_classes)))
    return tag_indicators

def parse_sitemaps(url, soup, response):    

    tag_indicators = []
    tree = sitemap_tree_for_homepage(url)
    print(tree)
    entries = set()
    for page in tree.all_pages():
        entries.update(page.url)
    tag_indicators.append(add_indicator(url, "4-sitemap_entries", entries))
    return tag_indicators

def parse_dom_tree(url, soup, response):
    tag_indicators = []
    for text in soup.find_all(text=True):
        text.replace_with("")
    for tag in soup.find_all():
        tag.attrs = {}
    tag_indicators.append(add_indicator(url, "3-dom-tree", soup.prettify()))
    return tag_indicators

def parse_images(url, soup, response):
    tag_indicators = []
    image_links = []
    for img in soup.find_all("img"):
        if img.has_attr("src") and img["src"].startswith("/"):
            image_links.append(url + img["src"])
        elif img.has_attr("src"):
            image_links.append(img["src"])
    for link in image_links:
        try:
            response = requests.get(link)
            img = Image.open(BytesIO(response.content))
            image_hash = imagehash.phash(img)
            tag_indicators.append(add_indicator(url, "3-image-phash", image_hash))
        except Exception as ex:
            continue  # print(ex.message)

    return tag_indicators


def add_verification_tags(url, name, content):
    return add_indicator(url, "1-verification_id", name + "|" + content)

def add_meta_social_tags(url, name, content):
    return add_indicator(url, "3-meta_social", name + "|" + content)
    
def add_script_src_tags(url,  content):
    return add_indicator(url, "3-script_src", content)
    
def add_link_tags(url, href):
    return add_indicator(url, "3-link_href", href)

def parse_meta_tags(url, soup, response):
    meta_tags = soup.find_all("meta")
    tag_indicators = []
    # Iterate over the meta tags
    for meta_tag in meta_tags:
        # Get the name and content attributes of the meta tags
        name = meta_tag.get("name")
        prop = meta_tag.get("property")
        content = meta_tag.get("content")
        if name and "verif" in name.lower():
            tag_indicators.append(add_verification_tags(url, name, content))
        elif name and name in ["twitter:site", "fb:pages"]:
            tag_indicators.append(add_meta_social_tags(url, name, content))
        elif (name or prop) and content:
            name = name or prop
            tag_indicators.append(add_meta_generic_tags(url, name, content))
    return tag_indicators

def parse_script_tags(url, soup, response):
    script_tags = soup.find_all("script")
    tag_indicators = []
    # Iterate over the meta tags
    for script_tag in script_tags:
        # Get the name and content attributes of the meta tags
        source = script_tag.get("src")
        if source:
            match = re.search(r"/([^/]+)$", source)
            if match:
                tag_indicators.append(add_script_src_tags(url, match.group(1)))
    return tag_indicators


def parse_id_attributes(url, soup, response):
    ids = [element['id'] for element in soup.find_all(id=True)]    
    id_indicators = [add_indicator(url, "3-id_tags", ','.join(ids))]
    return id_indicators

def parse_iframe_ids(url, soup, response):
    iframe_ids = [iframe['id'] for iframe in soup.find_all('iframe') if 'id' in iframe.attrs]
    iframe_indicators = []
    for iframe in iframe_ids:
        iframe_indicators.append(add_indicator(url, "3-iframe_id_tags", iframe))
    return iframe_indicators

def parse_link_tags(url, soup, response):
    
    link_tags = soup.find_all("link")
    tag_indicators = []
    # Iterate over the meta tags
    for link_tag in link_tags:
        # Get the name and content attributes of the meta tags
        href = link_tag.get("href")
        if href:
            tag_indicators.append(add_link_tags(url, href))
    return tag_indicators


def bulk_builtwith_query(domains: List[str], save_matches: bool = False):
    api_keys = yaml.safe_load(open("config/api_keys.yml", "r"))
    builtwith_key = api_keys.get("BUILT_WITH")
    if not builtwith_key:
        print("No Builtwith API key provided. Skipping.")
        return []
    techstack_indicators = get_techstack_indicators(
        domains=domains, api_key=builtwith_key
    )
    techidentifier_indicators = get_tech_identifiers(
        domains=domains, api_key=builtwith_key, save_matches=save_matches
    )
    return techstack_indicators + techidentifier_indicators


def get_techstack_indicators(domains: List[str], api_key: str):
    domain_list = ",".join(domains)
    tech_stack_query = (
        f"https://api.builtwith.com/v20/api.json?KEY={api_key}&LOOKUP={domain_list}"
    )
    try:
        api_result = requests.get(tech_stack_query)
        data = json.loads(api_result.content)
        # API supports querying multiple sites at a time, hence the embedded structure
        for result_item in data["Results"]:
            result = result_item["Result"]
            tech_stack = []
            for path in result["Paths"]:
                technologies = [
                    {
                        "indicator_type": "techstack",
                        "indicator_content": {
                            "name": tech.get("Name"),
                            "link": tech.get("Link"),
                            "tag": tech.get("Tag"),
                            "subdomain": path["SubDomain"],
                        },
                        "domain_name": domain,
                    }
                    for tech in path["Technologies"]
                ]
                tech_stack.extend(technologies)
            return tech_stack
    except IndexError:
        print(
            "Error hit iterating through results. Have you hit your Builtwith API limit?"
        )
        traceback.print_exc()
    except Exception:
        traceback.print_exc()
    finally:
        return []


def get_tech_identifiers(domains: List[str], api_key: str, save_matches: bool = False):
    domain_list = ",".join(domains)
    tech_relation_query = (
        f"https://api.builtwith.com/rv2/api.json?KEY={api_key}&LOOKUP={domain_list}"
    )
    api_result = requests.get(tech_relation_query)

    try:
        data = json.loads(api_result.content)
        for result_item in data["Relationships"]:
            relations = result_item["Identifiers"]
            matches_df = (
                pd.DataFrame(relations).explode("Matches").rename(columns=str.lower)
            )
            if save_matches:
                matches_df.to_csv(f"{domain}_identifier_matches.csv")
            identifiers = (
                matches_df.groupby(["type", "value"])["matches"]
                .count()
                .to_frame("num_matches")
                .reset_index()
            )
            # applying indicator structure
            return [
                {
                    "indicator_type": "tech_identifier",
                    "indicator_content": identifier,
                    "domain_name": domain,
                }
                for identifier in identifiers.to_dict(orient="records")
            ]
    except IndexError as e:
        print(
            "Error hit iterating through results. Have you hit your Builtwith API limit?"
        )
        traceback.print_exc()
    except Exception as e:
        traceback.print_exc()
    finally:
        return []


def add_meta_generic_tags(url, name, content):

    # Print the name and content attributes
    return {
        "indicator_type": "3-meta_generic",
        "indicator_content": name + "|" + content,
        "domain_name": get_domain_name(url),
    }


def parse_body(url, soup, response):
    text = response.text
    tag_indicators = []
    tag_indicators.extend(find_uuids(url, text))
    tag_indicators.extend(find_wallets(url, text))

    return tag_indicators


def find_with_regex(regex, text, url, indicator_type):
    tag_indicators = []
    matches = set(re.findall(regex, text))
    for match in matches:
        tag_indicators.append(add_indicator(url, indicator_type, match))
    return tag_indicators


def find_uuids(url, text):
    uuid_pattern = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    return find_with_regex(uuid_pattern, text, url, "3-uuid")

def find_wallets(url, text):

    tag_indicators = []
    crypto_wallet_pattern = "[^a-zA-Z0-9](0x[a-fA-F0-9]{40}|[13][a-zA-Z0-9]{24,33}|[4][a-zA-Z0-9]{95}|[qp][a-zA-Z0-9]{25,34})[^a-zA-Z0-9]"

    btc_address_regex = re.compile(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$')
    btc_matches = set(re.findall(btc_address_regex, text))
    # Get transaction data for the address from the BlockCypher API
    for match in btc_matches:
        tag_indicators.append(find_wallet_transactions(match, 'btc'))

    bch_address_regex = re.compile(r'^[qQ][a-km-zA-HJ-NP-Z1-9]{41}$')
    bch_matches = set(re.findall(bch_address_regex, text))
    # Get transaction data for the address from the BlockCypher API
    for match in bch_matches:
        tag_indicators.append(find_wallet_transactions(match, 'bch'))

    tag_indicators.extend(find_with_regex(crypto_wallet_pattern, text, url, "1-crypto-wallet"))
    return tag_indicators

def find_wallet_transactions(url, wallet_type, wallet):
    tx_data = blockcypher.get_address_full(wallet, coin_symbol=wallet_type)
    tag_indicators = []

    # Check if transaction data exists for the address
    if tx_data is not None:
        # Extract the addresses involved in transactions with the given address
        addresses = set()
        for input in tx_data['txs']:
            for address in input['addresses']:
                addresses.add(address)
        for address in addresses:
            tag_indicators.append(add_indicator(url, '2-crypto-transacation', address))
    return tag_indicators


def add_associated_domains_from_cert(url, soup, response):
    port = 443

    cert = ssl.get_server_certificate((get_domain_name(url), port))
    x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)

    sans = []
    for i in range(x509.get_extension_count()):
        ext = x509.get_extension(i)
        if ext.get_short_name() == b"subjectAltName":
            ext_val = ext.__str__()
            sans = ext_val.replace("DNS:", "").split(",")

    tag_indicators = []
    for san in sans:
        tag_indicators.append(add_indicator(url, "1-cert-domain", san))
    return tag_indicators


def find_google_analytics_id(url, text):
    ga_id_pattern = "(UA-\d{6,8}|UA-\d{6,8}-\d{1})"
    return find_with_regex(ga_id_pattern, text, url, "1-ga_id")

def find_google_tag_id(url, text):
    ga_id_pattern = "G-([A-Za-z0-9]+)"
    return find_with_regex(ga_id_pattern, text, url, "1-ga_tag_id")

def find_adobe_analytics_id(url, text):
    pattern = "s\.account\s*=\s*[\"']([^\"']+)[\"']"
    return find_with_regex(pattern, text, url, "1-adobe_analytics_id")

def find_facebook_pixel_id(url, text):
    pattern = "fbq\('init',\s*'(\d+)'\)"
    return find_with_regex(pattern, text, url, "1-fb_pixel_id")

def find_hotjar_id(url, text):
    pattern = "hjid\s*=\s*(\d+)"
    return find_with_regex(pattern, text, url, "1-hotjar_id")

def find_microsoft_clarity_id(url, text):
    pattern = "clarity\s*:\s*{.*?projectId\s*:\s*[\"']([^\"']+)[\"']"
    return find_with_regex(pattern, text, url, "1-ms_clarity_id")

def find_pinterest_tag_id(url, text):
    pattern = "pintrk\('load',\s*'([^']+)'\)"
    return find_with_regex(pattern, text, url, "1-pinterest_tag_id")

def find_linkedin_insight_id(url, text):
    pattern = "linkedin_insight\s*:\s*{.*?partnerId\s*:\s*(\d+)"
    return find_with_regex(pattern, text, url, "1-linkedin_insight_id")

def find_yandex_track_id(url, text):
    ga_id_pattern = "ym\(\d{8}"
    return find_with_regex(ga_id_pattern, text, url, "1-yandex_tag_id")


def parse_tracking_ids(url, soup, response):
    text = response.text
    tag_indicators = []
    tag_indicators.extend(find_google_analytics_id(url, text))
    tag_indicators.extend(find_google_tag_id(url, text))
    tag_indicators.extend(find_yandex_track_id(url, text))
    tag_indicators.extend(find_adobe_analytics_id(url, text))
    tag_indicators.extend(find_facebook_pixel_id(url, text))
    tag_indicators.extend(find_hotjar_id(url, text))
    tag_indicators.extend(find_linkedin_insight_id(url, text))
    tag_indicators.extend(find_microsoft_clarity_id(url, text))
    tag_indicators.extend(find_pinterest_tag_id(url, text))
    return tag_indicators


def add_cdn_domains(url, soup, response):
    tag_indicators = []

    img_tags = soup.find_all("img")
    domains = set()
    for img_tag in img_tags:
        src = img_tag.get("src")
        if src:
            domain = urlsplit(src).hostname
            domains.add(domain)
    for domain in domains:
        tag_indicators.append(add_indicator(url, "3-cdn-domain", domain))
    return tag_indicators


def add_domain_suffix(url, domain_suffix):
    return {
        "indicator_type": "1-domain_suffix",
        "indicator_content": domain_suffix,
        "domain_name": get_domain_name(url),
    }


# getting domain and suffix, eg -  “google.com”
def find_domain_suffix(url):
    tag_indicators = []
    ext = tldextract.extract(url)
    domain_suffix = ext[1] + "." + ext[2]
    tag_indicators.append(add_domain_suffix(url, domain_suffix))
    return tag_indicators  # joins the strings


def add_second_level_domain(url, domain):
    return {
        "indicator_type": "1-domain",
        "indicator_content": domain,
        "domain_name": get_domain_name(url),
    }


def find_second_level_domain(url):
    tag_indicators = []
    ext = tldextract.extract(url)
    domain = ext[1]
    tag_indicators.append(add_second_level_domain(url, domain))
    return tag_indicators


def parse_domain_name(url, soup, response):
    tag_indicators = []
    tag_indicators.extend(find_domain_suffix(url))
    tag_indicators.extend(find_second_level_domain(url))
    return tag_indicators

def start_urlscan(url):
    api_keys = yaml.safe_load(open("config/api_keys.yml", "r"))
    urlscan_key = api_keys.get("URLSCAN")
    if not urlscan_key:
        print("No urlscan API key provided. Passing...")
        return None
    headers = {"API-Key": urlscan_key, "Content-Type": "application/json"}
    data = {"url": url, "visibility": "public"}
    response = requests.post(
        "https://urlscan.io/api/v1/scan/", headers=headers, data=json.dumps(data)
    )
    submission_response = response.json()
    return submission_response["api"]


def add_urlscan_indicators(domain, urlscan_result_url):
    result = requests.get(urlscan_result_url)
    if result.status_code == 404:
        print("sleeping for urlscan results")
        time.sleep(20)
    data = result.json()
    urlscan_indicators = []
    urlscan_indicators.append(
        [
            {
                "indicator_type": "2-global_variable",
                "indicator_content": json.dumps(variable),
                "domain_name": domain,
            }
            for variable in data["data"]["globals"]
        ]
    )
    certs = data["lists"]["certificates"]
    urlscan_indicators.append(
        [
            {
                "indicator_type": "2-urlscan_certificate",
                "indicator_content": json.dumps(certificate),
                "domain_name": domain,
            }
            for certificate in certs
        ]
    )
    # wappalyzer is used to detect tech used in the website
    detected_tech = data["meta"]["processors"]["wappa"]["data"]
    urlscan_indicators.append(
        [
            {
                "indicator_type": "2-techstack",
                "indicator_content": tech["app"],
                "domain_name": domain,
            }
            for tech in detected_tech
        ]
    )
    return urlscan_indicators


# Send a GET request to the specified URL, ignoring bad SSL certificates
def get_endpoints(url,endpoints):
    for endpoint in endpoints:
        response = requests.get(f"{url}/{endpoint}", verify=False)
        if response.status_code == 200:
            return response.text
    return None


def parse_cms(url, soup, response):
    # TODO: add more CMSs
    cms_indicators = []
    cms = None    
    
    # Endpoints to check for
    wp_endpoints = ["wp-login.php", "wp-admin/"]
    joomla_endpoints = ["administrator/"]
    drupal_endpoints = ["user/login", "core/"]
    bitrix_endpoints = ["bitrix/admin/"]

    # Check for endpoints
    if get_endpoints(url, wp_endpoints) is not None:
        cms_indicators.extend(parse_wordpress(url))
        cms = "WordPress"
    if get_endpoints(url, joomla_endpoints)  is not None:
        cms = "Joomla"
    if get_endpoints(url, drupal_endpoints) is not None:
        cms = "Drupal"
    if get_endpoints(url, bitrix_endpoints) is not None:
        cms = "Bitrix"
    
    if cms is not None:
        cms_indicators.append(add_indicator(domain, "3-cms", cms))

    return cms_indicators

# For WordPress, check for endpoints, if they exist, get the items and add them as indicators
def parse_wordpress(url):

    wp_indicators = []
    endpoints = {
        'tags': "/wp-json/wp/v2/tags",
        'posts': "/wp-json/wp/v2/posts",
        'pages': "/wp-json/wp/v2/pages",
        'categories': "/wp-json/wp/v2/categories",
        'users': "/wp-json/wp/v2/users",
        'blocks': "/wp-json/wp/v2/blocks"
    }
    
    for key, val in endpoints.items():
        try:
            wp_items = json.loads(get_endpoints(url,[val]))
            wp_items_string = ""
            for wp_item in wp_items:
                wp_items_string += wp_item['slug'] + ","
            wp_indicators.append(add_indicator(url,'3-wp-'+key, wp_items_string ))
        except Exception as e:
            print(e.message)
            continue
    return wp_indicators

def detect_and_parse_feed_content(url, soup, response):
    feed_indicators = []
    feed = None    

    feed_endpoints = ["feed/", "rss/", "rss.xml"]
    feed = get_endpoints(url, feed_endpoints)

    if feed is not None:
        feed = feedparser.parse(url)
        for entry in feed.entries:
            feed_indicators.append(add_indicator(domain, "4-content-title", entry.title))
            feed_indicators.append(add_indicator(domain, "4-content-link", entry.link))
            feed_indicators.append(add_indicator(domain, "4-content-summary", entry.summary))
            feed_indicators.append(add_indicator(domain, "4-content-published", entry.published))

    return feed_indicators


def crawl(url, visited_urls, functions_to_run):
    indicators = []
    # Add the URL to the set of visited URLs
    domain = get_domain_name(url)
    visited_urls.add(domain)
    # Send a GET request to the specified URL, ignoring bad SSL certificates
    response = requests.get(url, verify=False)
    # Parse the HTML content of the page
    soup = BeautifulSoup(response.text, "html.parser")

       # Run only the functions that are specified
    for function_name in functions_to_run:
        try:
            function_to_run = INDICATOR_FUNCTIONS.get(function_name)
            if function_to_run:
                indicators.extend(function_to_run(url, soup, response))
        except Exception as e:
            print(f"Exception occurred while running {function_name}: {e}")

    try:
        indicators.extend(add_associated_domains_from_cert(url))
    except Exception as e:
        traceback.print_exc()
    #indicators.extend(parse_dom_tree(url, soup))

    return indicators


def write_indicators(indicators, output_file):
    attribution_table = pd.DataFrame(
        columns=["indicator_type", "indicator_content", "domain_name"],
        data=indicators,
    )
    # this is done so if anything bad happens to break the script, we still get partial results
    # this approach also keeps the indicators list from becoming huge and slowing down
    if Path(output_file).exists():
        attribution_table.to_csv(
            output_file,
            index=False,    
            mode="a",
            encoding="utf-8",
            header=False,
        )
    else:
        attribution_table.to_csv(
            output_file,
            index=False,
            mode="w",
            encoding="utf-8",
            header=True,
        )


INDICATOR_FUNCTIONS = {
    'add_response_headers': add_response_headers,
    'add_ip_address': add_ip_address,
    'add_who_is': add_who_is,
    'parse_meta_tags': parse_meta_tags,
    'parse_script_tags': parse_script_tags,
    'parse_iframe_ids': parse_iframe_ids,
    'parse_id_attributes': parse_id_attributes,
    'parse_link_tags': parse_link_tags,
    'parse_body': parse_body,
    'parse_google_ids': parse_tracking_ids,
    'add_cdn_domains': add_cdn_domains,
    'parse_domain_name': parse_domain_name,
    'parse_classes': parse_classes,
    'detect_and_parse_feed_content': detect_and_parse_feed_content,
    'parse_cms': parse_cms,
    #'parse_sitemaps': parse_sitemaps,
    'add_associated_domains_from_cert': add_associated_domains_from_cert,
    # Uncomment the following if needed
    # 'parse_images': parse_images,
    # 'parse_dom_tree': parse_dom_tree,
}



if __name__ == "__main__":
    visited_urls = set()
    parser = argparse.ArgumentParser(
        description="Match indicators across sites.", add_help=False
    )
    parser.add_argument(
        "-f",
        "--input-file",
        type=str,
        help="file containing list of domains",
        required=False,
        default=os.path.join(".", "sites_of_concern.csv"),
    )
    parser.add_argument(
        "-c", "--domain-column", type=str, required=False, default="Domain"
    )
    parser.add_argument(
        "-o",
        "--output-file",
        type=str,
        help="file to save final list of match results",
        required=False,
        default=os.path.join(".", "indicators_output.csv"),
    )

    args = parser.parse_args()
    domain_col = args.domain_column

    output_file = args.output_file
    input_data = pd.read_csv(args.input_file)
    domains = input_data[domain_col]
    for domain in domains:
        try:
            indicators = crawl(domain, visited_urls, INDICATOR_FUNCTIONS)
            write_indicators(indicators, output_file=output_file)
        except Exception as e:
            print(f"Failing error on {domain}. See traceback below. Soldiering on...")
            traceback.print_exc()
    # try:
    #     builtwith_indicators = bulk_builtwith_query(domains=domains, save_matches=False)
    #     write_indicators(builtwith_indicators, output_file=output_file)
    # except Exception as e:
    #     print("Builtwith indicators failed. Continuing on.")
    #print("Running urlscans")
   # url_scan_submissions = {}
    #for #domain in domains:
        # print(f"Collecting {domain}")
        #url_scan_submissions[domain] = start_urlscan(domain)
    # this way we can retry pulling if something fails
    #with open("urlscan_submissions.json", "w") as f:
        #json.dump(url_scan_submissions, f)
    #time.sleep(60)  # this should be replaced with more clever retrying
    #with open("urlscan_submissions.json", "r") as f:
        #rl_scan_submissions = json.load(f)

    # for domain, url_submission in url_scan_submissions.items():
    #     try:
    #         indicators = add_urlscan_indicators(domain, url_submission)
    #         write_indicators(indicators, output_file=output_file)
    #     except Exception as e:
    #         print(f"getting urlscan results for {domain} failed. continuing on.")
    #         print(traceback.print_exc())
