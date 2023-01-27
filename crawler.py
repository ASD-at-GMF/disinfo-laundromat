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
import sys
import ssl
from OpenSSL import crypto
import traceback
import yaml
import json
import tldextract
import imagehash
from PIL import Image
from pathlib import Path
from typing import List, Dict, Set

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
        "indicator_type": indicator_type,
        "indicator_content": indicator_content,
        "domain_name": get_domain_name(url),
    }


def add_ip_address(domain_name):
    ip_indicators = []
    if domain_name.startswith("https://"):
        host_name = domain_name[8:]
    else:
        host_name = domain_name

    try:
        # Resolve the domain name to an IP address
        ip_address = socket.gethostbyname(host_name)
        ip_indicators.append(add_indicator(domain, "ip", ip_address))

        last_period_index = ip_address.rfind(".")
        subnet_id = ip_address[:last_period_index]
        ip_indicators.append(add_indicator(domain, "subnet", subnet_id))
    except socket.gaierror:
        print("Could not resolve the domain name {}".format(domain_name))
    finally:
        return ip_indicators


def get_who_is(url):
    result = whois.whois(url)
    return str(result)

def add_who_is(url):
    whois_content = get_who_is(url)
    return add_indicator(get_domain_name(url), "whois", whois_content)

def parse_classes(url, soup):
    tag_indicators = []
    used_classes = set()
    for elem in soup.select("[class]"):
        classes = elem["class"]
        used_classes.update(classes)
    tag_indicators.append(add_indicator(url, "css-class", used_classes))
    return tag_indicators

def parse_dom_tree(url, soup):
    tag_indicators = []
    for text in soup.find_all(text=True):
        text.replace_with("")
    for tag in soup.find_all():
        tag.attrs = {}
    tag_indicators.append(add_indicator(url, "dom-tree", soup.prettify()))
    return tag_indicators

def parse_images(url, soup):
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
            tag_indicators.append(add_indicator(url, "image-phash", image_hash))
        except Exception as ex:
            continue  # print(ex.message)

    return tag_indicators


def add_verification_tags(url, name, content):
    return add_indicator(get_domain_name(url), "verification_id", name + "|" + content)

def add_meta_social_tags(url, name, content):
    return add_indicator(get_domain_name(url), "meta_social", name + "|" + content)

def parse_meta_tags(url, soup):
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

def parse_meta_tags(url, soup):

    meta_tags = soup.find_all("script")
    tag_indicators = []
    # Iterate over the meta tags
    for meta_tag in meta_tags:
        # Get the name and content attributes of the meta tags
        source = meta_tag.get("src")
        if source:
            tag_indicators.append(add_verification_tags(url, name, content))
        
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
        "indicator_type": "meta_generic",
        "indicator_content": name + "|" + content,
        "domain_name": get_domain_name(url),
    }


def parse_body(url, text):
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
    return find_with_regex(uuid_pattern, text, url, "uuid")


def find_wallets(url, text):
    crypto_wallet_pattern = "[^a-zA-Z0-9](0x[a-fA-F0-9]{40}|[13][a-zA-Z0-9]{24,33}|[4][a-zA-Z0-9]{95}|[qp][a-zA-Z0-9]{25,34})[^a-zA-Z0-9]"
    return find_with_regex(crypto_wallet_pattern, text, url, "crypto-wallet")


def add_associated_domains_from_cert(url):
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
    tag_indicators.append(add_indicator(url, "certificate", cert))
    for san in sans:
        tag_indicators.append(add_indicator(url, "cert-domain", san))
    return tag_indicators


def find_google_analytics_id(url, text):
    ga_id_pattern = "(UA-\d{6,8}|UA-\d{6,8}-\d{1})"
    return find_with_regex(ga_id_pattern, text, url, "ga_id")


def find_google_tag_id(url, text):
    ga_id_pattern = "G-([A-Za-z0-9]+)"
    return find_with_regex(ga_id_pattern, text, url, "ga_tag_id")


def find_yandex_track_id(url, text):
    ga_id_pattern = "ym\(\d{8}"
    return find_with_regex(ga_id_pattern, text, url, "yandex_tag_id")


def parse_google_ids(url, text):
    tag_indicators = []
    tag_indicators.extend(find_google_analytics_id(url, text))
    tag_indicators.extend(find_google_tag_id(url, text))
    tag_indicators.extend(find_yandex_track_id(url, text))
    return tag_indicators


def add_cdn_domains(url, soup):
    tag_indicators = []

    img_tags = soup.find_all("img")
    domains = set()
    for img_tag in img_tags:
        src = img_tag.get("src")
        if src:
            domain = urlsplit(src).hostname
            domains.add(domain)
    for domain in domains:
        tag_indicators.append(add_indicator(url, "cdn-domain", domain))
    return tag_indicators


def add_domain_suffix(url, domain_suffix):
    return {
        "indicator_type": "domain_suffix",
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
        "indicator_type": "domain",
        "indicator_content": domain,
        "domain_name": get_domain_name(url),
    }


def find_second_level_domain(url):
    tag_indicators = []
    ext = tldextract.extract(url)
    domain = ext[1]
    tag_indicators.append(add_second_level_domain(url, domain))
    return tag_indicators


def parse_domain_name(url):
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
    urlscan_indicators.extend(
        [
            {
                "indicator_type": "global_variable",
                "indicator_content": json.dumps(variable),
                "domain_name": domain,
            }
            for variable in data["data"]["globals"]
        ]
    )
    certs = data["lists"]["certificates"]
    urlscan_indicators.extend(
        [
            {
                "indicator_type": "urlscan_certificate",
                "indicator_content": json.dumps(certificate),
                "domain_name": domain,
            }
            for certificate in certs
        ]
    )
    # wappalyzer is used to detect tech used in the website
    detected_tech = data["meta"]["processors"]["wappa"]["data"]
    urlscan_indicators.extend(
        [
            {
                "indicator_type": "techstack",
                "indicator_content": tech["app"],
                "domain_name": domain,
            }
            for tech in detected_tech
        ]
    )
    return urlscan_indicators


def crawl(url: str, visited_urls: Set[str]) -> List[Dict[str, str]]:
    indicators = []
    # Add the URL to the set of visited URLs
    domain = get_domain_name(url)
    visited_urls.add(domain)
    # Send a GET request to the specified URL
    response = requests.get(url)

    # Parse the HTML content of the page
    soup = BeautifulSoup(response.text, "html.parser")

    # Print the DOM
    # print(soup.prettify())
    indicators.extend(add_ip_address(url))
    indicators.append(add_who_is(url))
    indicators.extend(parse_meta_tags(url, soup))
    indicators.extend(parse_body(url, response.text))
    indicators.extend(parse_google_ids(url, response.text))
    indicators.extend(add_associated_domains_from_cert(url))
    indicators.extend(add_cdn_domains(url, soup))
    indicators.extend(parse_domain_name(url))
    indicators.extend(parse_classes(url, soup))
    indicators.extend(parse_images(url, soup))
    indicators.extend(parse_dom_tree(url, soup))

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
                    # print(href)
                    continue
                except Exception:
                    continue

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


if __name__ == "__main__":
    visited_urls = set()
    parser = argparse.ArgumentParser(
        description="Match indicators across sites.", add_help=False
    )
    parser.add_argument(
        "-f",
        "--file",
        type=str,
        help="file containing list of domains",
        required=True,
    )
    parser.add_argument(
        "-c", "--domain-column", type=str, required=False, default="Domain"
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="file to save final list of match results",
        required=False,
    )

    args = parser.parse_args(sys.argv[1:])
    domain_col = args.domain_column
    output_file = args.output
    if output_file is None:
        output_file = Path(args.input).stem + "_indicators.csv"
    input_data = pd.read_csv(args.input)
    domains = input_data[domain_col]
    for domain in domains:
        try:
            indicators = crawl(domain, visited_urls)
            write_indicators(indicators, output_file=output_file)
        except Exception as e:
            print(f"Failing error on {domain}. See traceback below. Soldiering on...")
            traceback.print_exc()
    # try:
    #     builtwith_indicators = bulk_builtwith_query(domains=domains, save_matches=False)
    #     write_indicators(builtwith_indicators, output_file=output_file)
    # except Exception as e:
    #     print("Builtwith indicators failed. Continuing on.")
    print("Running urlscans")
    url_scan_submissions = {}
    for domain in domains:
        print(f"Collecting {domain}")
        url_scan_submissions[domain] = start_urlscan(domain)
    # this way we can retry pulling if something fails
    with open("urlscan_submissions.json", "w") as f:
        json.dump(url_scan_submissions, f)
    time.sleep(60)  # this should be replaced with more clever retrying
    with open("urlscan_submissions.json", "r") as f:
        url_scan_submissions = json.load(f)

    for domain, url_submission in url_scan_submissions.items():
        try:
            indicators = add_urlscan_indicators(domain, url_submission)
            write_indicators(indicators, output_file=output_file)
        except Exception as e:
            print(f"getting urlscan results for {domain} failed. continuing on.")
            print(traceback.print_exc())
