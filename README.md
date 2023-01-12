# The Disinformation Laundromat: An OSINT tool to expose mirror and proxy websites

The Disinformation Laundromat uses a set of indicators extracted from a webapge to make claims about who owns a collection of websites. 

## Tier 1: Conclusive
These indicators detemine with a high level of probability that a collection of sites is owned by the same entity. 
- Shared domain name
- IDs
  - Google Adsense IDs 
  - Google Analytics IDs 
  - SSO and Search engine verification ids: 
    - Google-site-verification
    - Facebook-domain-verification
    - Yandex-verification
    - Pocket-site-verification
- Crypto wallet ID 
- Multi-domain certificate 
- Shared social media sites in meta 
- (When not associated with a privacy guard) Matching whois information 
- (When not associated with a privacy guard) Shared IP address 
- Shared Domain name but different TLD 

## Tier 2: Associative
These indicators point towards a reasonable likelihood that a collection of sites is owned by the same entity. 

- Shared Content Delivery Network (CDN) 
- Shared subnet, e.g 121.100.55.*22* and 121.100.55.*45*
- Any matching meta tags
- Highly similar DOM tree

## Tier 3: Tertiary 
These indicators can be circumstantial correlations and should be substantiated with indicators of higher certainty. 

- Shared Architecture 
  - OS
  - Content Management System (CMS)
  - Platforms
  - Plugins
  - Libraries
  - Hosting
- Any Universal Unique Identifier (UUID)
- Highly similar images (as determined by pHash difference)
- Many shared CSS classes 

# How to use

Included with this tool is a small database of indicators for known sites. For more on creating your own corpus see 'Creating your own corpus' below. 

## Installation 
This tool requires Python 3 and PIP to run and can be obtained by downloading this repository or cloning it using git:
```
git clone https://github.com/pbenzoni/disinfo-laundromat.git 
```
### Installing requirements 

Once the code is downloaded and you've navigated to the project, install the necessary packages
```
pip install -r requirements.txt
```
## Comparing to existing indicator corpus
To check matches within the existing corpus (e.g. with {a.com, b.com, and c.com}, comparisons will be conducted between a.com and b.com, b.com and c.com, and a.com and c.com), use the following command:
```
py match.py
```

To check a given url against the corpus, run the following command: 
```
py match.py -domain <domain-to-be-searched>
```

## Generating a new indicator corpus
To generate a new indicator corpus, (a list of indicators assocaited with each site), run the following command:
```
py crawler.py <input-filename>.csv  <output-filename>.csv
```
by default, input-filename.csv must contain at least one column of urls with the header 'domain_name' but may contain any number of other columns. Entries in the 'domain_name' column must be formatted as 'https://subdomain.domain.TLD with no trailing slashes. The subdomain field is optional, and each uniques subdomain will be treated as a new site. The TLD may be any widely supported tld, (e.g. .com, .co.uk, .social, etc.)

# Fixes and Features Roadmap
- Update requirements.txt to reflect all required libraries
- Supporting similarity matching for existing indicators
- Adding support for adding new matching functions via a data dictionary
- Add aditionnal Indicators:
  - Shared usernames
  - Similar Privacy Policies
  - Shared contact informaiton
  - Similar sitemaps
  - Similar content
  - Similar external endpoint calls
- Parsing internal pages for additional textual indicators
- Intergration with a search api to find mirror site and other leads from across the web

