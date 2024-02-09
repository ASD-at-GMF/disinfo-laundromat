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

### About the Indicator Tier System

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

## Interpreting Results

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
