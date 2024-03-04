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
- Wikipedia's  list of [fake news websites](https://en.wikipedia.org/wiki/List_of_fake_news_websites) and Wikidata's [list of news websites](https://www.wikidata.org/w/index.php?title=Special:WhatLinksHere/Q17232649&limit=50&dir=next&offset=0%7C3014523)
- At our own discretion, user-input sites. (As of March 2024, no user input sites are included) 

Inclusion in the corpus of comparison sites is neither an endorsement nor a criticism of a given website's point of view or their relationship to any other member of the corpus. It solely reflects what websites are of interest to OSINT researchers. If you'd like a website removed from the list or have a potential list of new items to include, email pbenzoni (at) gmfus.org

Suggested for future inclusion, but not yet evaluated:
- 
- 
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

## Full Indicators List: 
- **1-cert-domain - Domain Certificate**:
An SSL certificate is a digital certificate that authenticates a website's or multiple websites' identity and enables an encrypted connection. *A shared certificate between two sites is strong evidence of a link between sites, as typically a certificate must be issued for all those sites at once by a single entity and cannot easily be spoofed. However, some web hosting and DDOS protection services bundle certificates for unrelated sites, so carefully research any matches.*

- **1-crypto-wallet - Cryptocurrency Wallet**:
A digital wallet used to store, send, and receive cryptocurrencies like Bitcoin and Ethereum. *The presence of a cryptocurrency wallet address can link a site or an individual to cryptocurrency transactions, potentially indicating financial sources or preferences. However, due to the pseudonymous nature of such wallets, additional information is required to definitively establish ownership or connections.*

- **1-domain - Domain Name**:
The unique name that identifies a website, which is registered in the Domain Name System (DNS). *The domain name can provide insights into the nature or origin of a website. Commonalities in domain names may suggest shared affiliations or intents. However, the ease of registering domain names requires careful analysis to avoid false associations.*

- **1-domain_suffix - Domain Suffix**:
The last part of a domain name, typically representing a category or country code. *A domain suffix can indicate the intended audience or origin of a website. Similar suffixes across different sites might suggest a geographical or organizational link. Yet, the global accessibility of most suffixes means this should not be a sole determinant of connection.*

- **1-fb_pixel_id - Facebook Pixel ID**:
A unique identifier for the Facebook Pixel, an analytics tool that allows website owners to measure the effectiveness of their advertising by understanding the actions people take on their website. *Shared Facebook Pixel IDs across sites can indicate common ownership or a shared marketing strategy. However, third-party marketing agencies might use the same ID across different clients, potentially leading to mistaken connections.*

- **1-adobe_analytics_id - Adobe Analytics ID**:
A unique identifier used by Adobe Analytics, a tool for analyzing visitor traffic on websites. *Similar to other analytics tools, shared Adobe Analytics IDs can hint at common management or partnerships between websites. However, as with Facebook Pixel IDs, the use of analytics IDs by third-party services may introduce unrelated links.*

- **3-sitemap_entries - Sitemap Entries**:
Entries in a website's sitemap, which is an XML file listing the URLs for a site along with additional metadata about each URL. *Analysis of sitemap entries can reveal the structure and content priorities of a website. Commonalities in sitemap structures or content might suggest shared authorship or objectives. However, similarities could also result from common website templates or platforms.*

- **3-ipms_domain_iprangeowner_cidr - IP Range Owner CIDR**:
The Classless Inter-Domain Routing (CIDR) notation indicating the range of IP addresses owned by an entity. *CIDR data can help identify the network scope and location of a domain's hosting. Shared IP ranges might suggest hosting or service provider commonalities. However, large hosting providers may have numerous unrelated clients within the same range.*

- **3-ipms_domain_iprangeowner_ownerName - IP Range Owner Name**:
The name of the entity owning a range of IP addresses. *This information can be used to identify the hosting provider or organization controlling a set of IP addresses. Shared ownership names might indicate a relationship between the entities using those IPs, though large organizations often host unrelated entities.*

- **3-ipms_domain_iprangeowner_address - IP Range Owner Address**:
Physical address of the entity owning a range of IP addresses. *Physical addresses can provide geographical and organizational context. Shared addresses across different IP ranges might suggest a close relationship or common management. However, the presence of data centers and shared office spaces can result in address overlaps for unrelated entities.*

- **3-ipms_domain_nameserver - Domain Name Server**:
A server that translates domain names into IP addresses, facilitating the connection between a user's device and the website's server. *Common nameservers among different domains might indicate shared hosting or management services. However, popular hosting providers serve a large number of clients, potentially leading to false associations.*

- **3-ipms_domain_otheripused - Other IPs Used by Domain**:
A list of IP addresses that have been used by a domain, aside from its primary IP address. *This data can reveal the network history and changes in hosting of a domain. Shared historical IPs might suggest past commonalities or transitions in hosting services. However, dynamic IP allocation by hosting services can result in unrelated sites temporarily sharing IPs.*

- **3-ipms_siteonthisip_now - Current Sites on This IP**:
Websites currently hosted on the same IP address. *Websites sharing an IP address may have a relationship, such as being part of the same network or organization. However, shared hosting environments can lead to unrelated websites being hosted on the same IP.*

- **3-ipms_siteonthisip_before - Former Sites on This IP**:
Websites that were previously hosted on the same IP address but are no longer. *Historical data on IP hosting can provide insights into the network associations and changes over time. Formerly shared IPs might indicate previous relationships or common hosting decisions. However, dynamic IP allocations can lead to brief and incidental overlaps.*

- **3-ipms_siteonthisip_broken - Broken Sites on This IP**:
Websites hosted on the same IP address that are currently not functional or accessible. *Identifying non-functional sites on a shared IP can indicate network health or hosting issues. Patterns in broken sites might suggest targeted disruptions or poor hosting services. However, temporary technical issues can also cause sites to be non-functional, unrelated to their network neighbors.*

- **3-ipms_useragents - User Agents**:
Strings that web browsers and other client devices send to identify themselves to web servers, typically containing information about the device and browser. *Analysis of user agents can reveal the types of devices and browsers most frequently accessing a site, potentially indicating the site's target audience or technological preferences. However, the widespread use of common browsers can limit the specificity of these insights.*

- **1-ip_shodan_hostnames - Shodan Hostnames**:
Hostnames associated with an IP address as indexed by Shodan, a search engine for internet-connected devices. *Shodan's data can reveal the various services and hostnames associated with an IP, potentially indicating its use and ownership. Shared hostnames across IPs might suggest network or organizational links. However, the dynamic nature of IP allocations can lead to transient or outdated hostname associations.*

- **3-ip_shodan_ports - Shodan Ports**:
Open network ports on an IP address as detected by Shodan. *Open ports can indicate the types of services an IP is offering, with certain ports associated with specific applications or protocols. Common ports across different IPs might suggest similar uses or configurations. However, standard port uses can be widespread and not necessarily indicative of direct relationships.*

- **2-ip_shodan_vuln - Shodan Vulnerabilities**:
Vulnerabilities identified on an IP address by Shodan, based on open ports and services. *Identifying vulnerabilities can help assess the security posture of a network or device. Shared vulnerabilities might indicate common software or configuration weaknesses. However, widespread vulnerabilities in popular software can appear across unrelated networks.*

- **3-ip_shodan_cpe - Shodan CPE**:
Common Platform Enumeration (CPE) identifiers found by Shodan, indicating specific software or hardware on an IP. *CPE identifiers can provide detailed insights into the technological stack of a network or device. Shared CPEs might suggest technological commonalities or shared suppliers. However, the ubiquity of certain technologies can lead to coincidental overlaps.*

- **1-ga_id - Google Analytics ID**:
A unique identifier associated with Google Analytics, used for tracking and analyzing website traffic. *Like other analytics IDs, shared Google Analytics IDs across websites may indicate common ownership or marketing strategies. However, the use of third-party marketing agencies can result in the same ID being used across unrelated sites.*

- **1-ga_tag_id - Google Analytics Tag ID**:
A unique tag identifier used in Google Analytics for tracking specific user interactions on a website. *Similar to the general Google Analytics ID, shared tag IDs might suggest a connection between sites, especially in how they track user behavior. However, similar tracking strategies might also be independently adopted by unrelated sites.*

- **1-ip - IP Address**:
A unique numerical label assigned to each device connected to a computer network that uses the Internet Protocol for communication. *An IP address can reveal the geographic location and network provider of a device or website. Shared IPs may indicate shared hosting or network resources. However, dynamic IP allocation and large hosting environments can lead to incidental sharing.*

- **1-verification_id - Verification ID**:
A unique identifier used for verifying ownership or authenticity of a website or online account. *Verification IDs can establish the legitimacy of a site or account, potentially linking it to a specific owner or organization. However, verification processes vary, and IDs can be reassigned or spoofed, requiring careful verification.*

- **1-yandex_tag_id - Yandex Tag ID**:
A unique identifier used by Yandex Metrica, a tool for analyzing visitor traffic, similar to Google Analytics. *Shared Yandex Tag IDs could suggest common ownership or similar web analytics strategies between sites. However, like other analytics tools, the involvement of third-party services can create misleading connections.*

- **2-subnet - Subnet**:
A segment of a network's IP address range that can be designated to optimize performance and security. *Subnet information can indicate how a network is structured and segmented for various purposes. Shared subnets between different entities might suggest a relationship or common network management. However, subnets are often allocated by ISPs or hosting providers to multiple clients.*

- **3-cdn-domain - CDN Domain**:
A domain used by a Content Delivery Network (CDN) to deliver content efficiently across the internet. *Shared CDN domains can indicate that websites are utilizing the same CDN provider for content distribution, which might imply performance or operational preferences. However, popular CDNs are used by a wide range of websites, limiting the value of this data for establishing direct connections.*

- **3-cms - Content Management System**:
A software application or set of related programs used to create and manage digital content. *Common CMS platforms among different websites might suggest similar operational needs or preferences. However, widely-used CMS platforms like WordPress are employed by a diverse array of sites, often without any direct relation.*

- **3-css_classes - CSS Classes**:
Classes defined in Cascading Style Sheets (CSS) to style and format the layout of web pages. *Analysis of CSS classes can provide insights into the design and development approaches of a website. Shared classes might suggest common design templates or developers. However, common frameworks and libraries can lead to similar CSS classes across unrelated sites.*

- **3-header-nonstd-value - Non-Standard Header Value**:
Values in HTTP headers that do not conform to standard header formats, potentially indicating custom configurations or software. *Non-standard header values can be unique identifiers of custom configurations or software used by a website. Shared non-standard values might indicate common development practices or software choices. However, the interpretation of these values requires technical expertise to avoid misattribution.*

- **3-header-server - Server Header**:
The 'Server' HTTP header field that specifies information about the software used by the origin server. *The server header can reveal the web server software and its configuration. Shared server headers might indicate similar technological choices or configurations. However, popular server software like Apache and Nginx is widely used, so this data alone is not sufficient to establish a connection.*

- **3-id_tags - ID Tags**:
Unique identifiers used in the HTML code of a website to distinguish specific elements. *Similar ID tags across websites might suggest shared development practices or template usage. However, common ID tags can also be a result of widespread frameworks or libraries, and thus, might not be indicative of direct relationships.* 

- **3-iframe_id_tags - Iframe ID Tags**:
Unique identifiers used for 'iframe' elements in HTML, allowing the embedding of an external webpage within a webpage. *Shared Iframe ID tags could indicate similar website functionalities or content sharing strategies. However, common frameworks or website templates can lead to the usage of similar Iframe IDs across different websites, reducing the significance of this correlation.* 

- **3-link_href - Link Href Attributes**:
The 'href' attribute of a link in HTML, specifying the URL of the page the link goes to. *Analysis of 'href' attributes can reveal the external connections or references a website makes. Shared 'href' attributes across different sites might suggest common affiliations or sources. However, links to popular or general websites might not be indicative of a direct relationship.* 

- **3-meta_generic - Generic Meta Tags**:
Meta tags in HTML that provide general information about a webpage, such as description, keywords, and author. *Common meta tags can indicate similar content or objectives. However, generic or broadly used tags may appear in a wide range of websites, potentially leading to mistaken connections.* 

- **3-meta_social - Social Media Meta Tags**:
Meta tags specifically designed for optimizing social media sharing, defining how content appears when shared on social platforms. *Shared social media meta tags might suggest a coordinated approach to social media engagement or content strategy. However, the use of standard social media optimization practices can lead to similar tags across unrelated sites.* 

- **3-script_src - Script Source Attributes**:
The 'src' attribute of a script tag in HTML, indicating the source of a JavaScript file. *Shared script sources can point to the use of common libraries or external scripts. However, the widespread use of popular JavaScript libraries and scripts might lead to coincidental similarities.* 

- **3-uuid - UUID**:
Universally Unique Identifier, a 128-bit number used to identify information in computer systems. *UUIDs can be used to track and manage assets or components within a system. Shared UUIDs might indicate a connection between different systems or components. However, the nature of UUIDs as unique identifiers typically limits the occurrence of shared UUIDs across unrelated systems.* 

- **3-whois_creation_date - WHOIS Creation Date**:
The date a domain name was first registered, as recorded in the WHOIS database. *Similar creation dates for domains might suggest a coordinated launch or common origin. However, coincidental registration dates are possible, especially during popular events or domain sales.* 

- **3-whois_server - WHOIS Server**:
The server that provides the WHOIS information, containing details about domain name registrations. *Use of the same WHOIS server for different domains could indicate a preference for certain domain registrars. However, popular registrars serve a large number of clients, so this alone isn't a strong indicator of a relationship.* 

- **3-whois-registrar - WHOIS Registrar**:
The organization authorized to register and manage domain names for a particular top-level domain. *Domains registered through the same registrar might have some administrative commonalities. However, given the market dominance of certain registrars, this is not a definitive sign of a direct connection between domain owners.* 

- **3-wp-blocks - WordPress Blocks**:
Content blocks used in WordPress to build and design webpages. *Shared WordPress blocks could indicate similar website designs or use of common templates. However, due to the popularity of WordPress and its wide range of available blocks, similarities might occur coincidentally.* 

- **3-wp-categories - WordPress Categories**:
Categorization system in WordPress used to group content into different sections. *Similar categories in different WordPress sites might suggest related content or thematic similarities. However, common categories are widely used across various sites, potentially leading to non-significant matches.* 

- **3-wp-pages - WordPress Pages**:
Web pages created and managed within the WordPress platform. *Analysis of WordPress pages can reveal the structure and content emphasis of a site. Shared page structures or content might suggest a common template or designer. However, the extensive use of WordPress templates can lead to similar page structures across unrelated sites.* 

- **3-wp-posts - WordPress Posts**:
Blog posts or articles published on a WordPress website. *Shared themes or styles in WordPress posts might indicate similar content strategies or sources. However, the widespread use of WordPress for blogging and content creation means that thematic overlaps are common and not necessarily indicative of a connection.* 

- **3-wp-tags - WordPress Tags**:
Tagging system in WordPress used to describe specific details of posts, aiding in content organization and navigation. *Common tags across WordPress sites might suggest related topics or a shared content approach. However, popular tags are frequently used across diverse websites, diminishing the potential for meaningful connections.* 

- **3-wp-users - WordPress Users**:
Individual accounts within WordPress that have various roles and permissions for managing website content. *Shared user accounts or roles across WordPress sites might imply common administration or authorship. However, generic user roles such as 'administrator' or 'editor' are common and not uniquely identifying.* 

- **2-urlscan_globalvariable - URLScan Global Variable**:
Global JavaScript variables identified by URLScan, a tool for scanning and analyzing websites. *Shared global variables might indicate the use of similar scripts or frameworks. However, common JavaScript practices and libraries can result in widespread use of the same global variables across different websites.* 

- **2-urlscan_cookies - URLScan Cookies**:
Cookies identified by URLScan as being set by websites during a scan. *Analysis of cookies can reveal tracking, personalization, or functional aspects of a website. Shared cookies across sites might suggest shared tracking or management tools. However, common third-party services, like analytics or advertising platforms, often set similar cookies across various websites.* 

- **2-urlscan_consolemessages - URLScan Console Messages**:
Messages output to the browser console during a website scan by URLScan. *Console messages can provide insights into the website's functionality or potential issues. Common messages across different scans might indicate similar development practices or shared issues. However, these messages can also be generated by common frameworks or browser extensions.* 

- **2-urlscan_asn - URLScan Autonomous System Number**:
The Autonomous System Number (ASN) identified by URLScan, representing the collection of IP networks and routers under the control of one entity. *Shared ASNs can suggest that websites are part of the same network or hosted by the same provider. However, large hosting providers and ISPs control extensive ASNs that encompass a wide range of clients.* 

- **2-urlscan_domainsonpage - URLScan Domains on Page**:
A list of all domains found on a webpage during a URLScan. *Domains listed on a page can reveal external links or embedded content. Shared domains across different webpages might suggest common affiliations or sources. However, widely used domains, such as social media or analytics platforms, are commonly found across numerous sites.* 

- **2-urlscan_urlssonpage - URLScan URLs on Page**:
All URLs found on a webpage during a URLScan. *The presence of specific URLs can indicate the nature of the content or the external connections of a website. Shared URLs across different pages might suggest a relationship or common sources. However, links to popular websites or resources might not be uniquely significant.* 

- **2-urlscanhrefs - URLScan Hrefs**:
Hypertext references (hrefs) identified on webpages during a URLScan. *Href attributes can provide insights into the external links and relationships of a website. Common hrefs across different sites might suggest shared affiliations or content. However, links to widely used resources or platforms can appear across many sites, limiting the potential for direct connection inference.* 

- **2-techstack - Technology Stack**:
The set of technologies used to build and run a website or application, including frameworks, languages, and software. *Similar technology stacks can suggest shared development practices or preferences. However, certain technology combinations are widely popular and may be used by a vast range of unrelated websites or applications.* 



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
