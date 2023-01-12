# The Disinformation Laundromat: An OSINT tool to expose mirror and proxy websites

The Disinformation Laundromat uses a set of indicators extracted from a webapge to make claims about who owns a collection of websites. 

## Tier 0: Open Admission
These indicators  overtly demonstrate shared ownership across examined sites: 

- Shared domain name

## Tier 1: Conclusive
These indicators detemine with a high level of probability that a collection of sites is owned by the same entity. 
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

# Fixes and Features Roadmap
- Update requirements.txt to reflect all required libraries
- Add aditionnal Indicators:
  - Shared usernames
  - Similar Privacy Policies
  - Shared contact informaiton
  - Similar sitemaps
  - Similar content
  - Similar external endpoint calls
- Parsing internal pages for additional textual indicators
- Intergration with a search api to find mirror site and other leads from across the web

