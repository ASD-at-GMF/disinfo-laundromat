# About
The purpose of the laundromat, how to use it effectively, and how to interpret the results 

## The Laundromat
The laundromat tool is a **lead generation tool** to try and determine if and how websites share architecture and content. *Even the strongest evidence from the laundromat tool requires corroboration through further investigation and additional evidence*

The laundromat tool provides two functions: Content Similarity Search and Domain Forensics Matching:

- Content Similarity Search attempts to detect URLs where a given text snippet occurs. It does not provide evidence of where that text originated or any relationship between two entities posting two similar texts. Detemination of a given text's provenance is outside the scope of this tool.
- Domain Forensics Matching attempts to find aspects of a website which indicate what makes it unique, give insight into its architecture/design, or show how its used/tracked. These indicators are compared for items with high degrees of similarity and matches are provided to the user

### The Domain Forensics Comparison Corpus

Any URLs entered into the Domain Forensics Matching tool are compared against against a list of domains already processed by the tool. This corpus is sourced from a number of sources, including: 

- [EU vs Disinfo's Database](https://euvsdisinfo.eu/disinformation-cases/)
- Research from partner and related organizations, such as [ISD's report on RT Mirror Sites](https://isdglobal.org/digital_dispatches/rt-articles-are-finding-their-way-to-european-audiences-but-how/)
- Known [state media sites](https://github.com/ASD-at-GMF/state-media-profiles)
- Lists of [pink slime sites](https://iffy.news/pink-slime-fake-local-news/) and [faux local news sites](https://www.midwestradionetwork.com/)
- Dave Troy's list of potential ['Russia Adjacent' sites](https://docs.google.com/spreadsheets/d/1JIHe_RqyRVO9JR1yR7AqEYqcLg9uimidiiEcVnlDnbA/edit#gid=0) 
- At our own discretion, user-input sites. 

Inclusion in the corpus of comparison sites is neither an endorsement nor a criticism of a given website's point of view or their relationship to any other member of the corpus. It solely reflects what websites are of interest to OSINT researchers. If you'd like a website removed from the list or have a potential list of new items to include, email pbenzoni (at) gmfus.org

Suggested for future inclusion, but not yet evaluated:
- https://en.wikipedia.org/wiki/List_of_fake_news_websites
- [List of news websites](https://www.wikidata.org/w/index.php?title=Special:WhatLinksHere/Q17232649&limit=50&dir=next&offset=0%7C3014523)

### About the Indicator Tier System and Interpreting Results

Each indicator is associated with evidentiary tier and are subject to [interpretation](#Interpreting Indicator Validity). 

Tier 1 indicators: [**WHEN VALID**](#Interpreting Indicator Validity) are typically unique or highly indicative of the provenance of a website. This includes unique IDs for verification purposes and web services like Google, Yandex, etc as well as site metadata like WHOIS information and certification, [**WHEN VALID**](#Interpreting Indicator Validity), as DDOS protection services like Cloudflare and shared hosting services like Bluehost can provide spurious matches. 

Tier 2 indicators: Tier 2 indicators, [**WHEN VALID**](#Interpreting Indicator Validity), offer a moderate level of certainty regarding the provenance of a website. These are not as unique as Tier 1 indicators but provide valuable context. This tier includes IPs within the same subnet, matching meta tags, and commonalities in standard and custom response headers

Tier 3: Tertiary Indicators
Tier 3 indicators, [**WHEN VALID**](#Interpreting Indicator Validity),  are the least specific but can still support broader analyses when combined with higher-tier indicators. These include shared CSS classes, UUIDs, and Content Management Systems 

#### Interpreting Indicator Validity
Understanding the validity of indicators is crucial in the analysis of websites' provenance and connections. Indicators can range from high-confidence markers of direct relationships to spurious matches that may mislead investigations. It is essential to approach each indicator with a critical eye and corroborate findings with additional evidence.

**High Confidence Indicators:**

- Unique IDs for verification purposes: These are often excellent evidence of a connection or shared ownership, such as unique Google Analytics IDs that directly link websites to the same account.
- Domain Certificate sharing: When websites share a specific SSL certificate, it often (but not always, see below) indicates a direct relationship, as certificates are typically issued to and managed by the same entity.

Discovering two websites with the same unique Google Analytics ID AND a shared, specific SSL certificate suggests a high-confidence link, indicating shared management or ownership.

**Spurious Matches:**

- Using services like Cloudflare: While Cloudflare and similar DDOS protection services offer valuable security benefits, they also mask true IP addresses and distribute shared SSL certificates across multiple sites. This can lead to false positives in linking unrelated websites based on shared IP addresses or certificates.
- Shared hosting services: Websites hosted on shared services like Bluehost may share IP addresses with hundreds of unrelated sites, making IP-based matches unreliable without further context.

Identifying that multiple websites are behind Cloudflare does not inherently indicate a connection beyond choosing a common, popular service for performance and security enhancements. All tier 1 and 2 indicators should be scrutinized carefully to determine if a match is valid or spurious

##### Example Investigation:

An analyst investigating a network of disinformation websites notices that several sites share a specific Facebook Pixel ID, indicating a potential link in their online marketing strategies. This Tier 1 indicator suggests a high-confidence connection. However, upon further investigation, it's revealed that these sites also use Cloudflare for DDOS protection, sharing SSL certificates and IP addresses with numerous unrelated sites. While the shared Facebook Pixel ID remains a strong indicator of connection, the shared certificates and IP addresses through Cloudflare are deemed spurious matches and the additional sites are discarded from the network. The analyst corroborates the initial finding with additional Tier 1 indicators, such as unique verification IDs, solidifying the connection between the sites beyond the spurious matches introduced by shared security services.

In interpreting indicator validity, analysts must weigh the evidence, seek corroboration, and consider the broader context to distinguish between high-confidence connections and potentially misleading, spurious matches.

## How to use the Laundromat

### Content Similarity Search

Content Similarity Search takes a given title and/or content and uses [GDELT](https://www.gdeltproject.org/), a variety of search services, and a plagiarism checker to detect urls with some degree of similarity of the provided content.

#### URL Search

Enter the full URL of an article or webpage (e.g. https://tech.cnn.com/article-title.html or https://www.rt.com/russia/588284-darkening-prospects-ukraine-postwar/) to automatically attempt to extract title and content 

#### Advanced (Title/Content) Search

This search allows users to specify the title and content (and apply boolean ANDs/ORs to the title and content). It also requires specifying a country and language to search in. As not all languages and countries are supported by each service, these will default to US and English if unsupported. Finally, users may specify which search engines they want to use for their search. 

This will produce a searchable list of links, their domains, possible associations with known lists, the title and snippet, the search engines where that link will be found, and the percentage of the title or snippet which matches the provided inputs as determined by the [Ratcliff/Obershelp algorithm.](https://en.wikipedia.org/wiki/Gestalt_pattern_matching).

### Domain Forensics Matching

This search, which will accept a list of one or more [fully qualified domain names.](https://en.wikipedia.org/wiki/Fully_qualified_domain_name) (including a prepended https:// on each domain name). This will produce a list of indicators and a list of sites which match (or are extremely similart to) those indicators. Indicators, and thus matches, are broken into the three tiers described above.  

## Partners, Sponsors, Disclaimers
The Laundromat Tool is made possible with the support of European Media and Information Fund (EMIF).
[<img src="https://securingdemocracy.gmfus.org/wp-content/uploads/2024/02/EMIF_Horizontal_logo_Black.png" alt="MJRC Logo" height="256"/>](https://gulbenkian.pt/emifund/) 
The Information Laundromat Tool is built a partnership of the Alliance for Securing Democracy (ASD), the Institute for Strategic Dialogue (ISD), and the University of Amsterdam (UvA) through the Digital Methods Institute. 

## Disclaimers
### Opinions Disclaimer
The sole responsibility for any content supported by the European Media and Information Fund lies with the author(s) and it may not necessarily reflect the positions of the EMIF and the Fund Partners, the Calouste Gulbenkian Foundation and the European University Institute.

### GDPR Disclaimer

The Information Laundromat tool is committed to protecting and respecting your privacy in compliance with the General Data Protection Regulation (GDPR). This disclaimer outlines the nature of the data processing activities conducted by our tool and your rights as a data subject.

#### Data Collection and Use

The Information Laundromat tool collects data through two forms, as part of its functions: Content Similarity Search and Domain Forensics Matching.

- **Content Similarity Search**: This function processes URLs and text snippets provided by the user to detect occurrences of the given text across various websites. It is important to note that the provenance of the text and the relationship between entities posting similar texts are not determined by this tool.
  
- **Domain Forensics Matching**: This function processes a domain URL and analyzes aspects of website architecture, design, and usage to identify unique indicators. It compares these indicators across websites to find high degrees of similarity and provides indicators and match results to the user.

#### Purpose of Processing

The form data and results are collected and are solely used for the purpose of usage analytics and potential corpus expansion. 

#### Data Subject Rights

Under GDPR, you have various rights concerning the processing of your personal data, including:

- The right to access your personal data.
- The right to rectification if your data is inaccurate or incomplete.
- The right to erasure of your data ("the right to be forgotten").
- The right to restrict processing of your data.
- The right to data portability.
- The right to object to data processing.
- The right to lodge a complaint with a supervisory authority.

Please note that exercising some of these rights may impact the functionality of the tool in relation to your use.

#### Data Security and Retention

We implement appropriate technical and organizational measures to ensure a level of security appropriate to the risk of the data processing activities. Data is retained only for as long as necessary for the purposes for which it was collected.

#### Contact Information

For any inquiries or requests regarding your data rights, please contact our data protection officer at pbenzoni (at) gmfus.org.

#### Consent

By using the Information Laundromat tool, you acknowledge that you have read this disclaimer and agree to the processing of your data as described herein. If you do not agree with these terms, please do not use the tool.

This disclaimer is subject to updates and modifications. Users are encouraged to review it periodically.
