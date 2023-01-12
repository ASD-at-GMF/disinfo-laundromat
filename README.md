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
- Shared Content Delivery Network (CDN) 
- Shared Domain name but different TLD 

## Tier 2: Associative
These indicators point towards a reasonable likelihood that a collection of sites is owned by the same entity. 

- Shared subnet, e.g 121.100.55._22_ and 121.100.55._45_
- Any matching meta tags (done)

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
