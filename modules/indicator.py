from typing import Any, Union

from modules.indicators import (EMBEDDED_IDS, FINANCIAL_IDS, SOCIAL_MEDIA_IDS,
                                TRACKING_IDS)

class Indicator:

    def __init__(self, type: str, content: Any, domain: str | None = None):
        self.type = type
        self.content = content
        self.tier = INDICATOR_TYPES[self.type]['tier']
        self.domain = domain

    def to_dict(self):
        return {
        "indicator_type": self.type,
        "indicator_content": self.content,
        "indicator_tier": self.tier
    }
    
INDICATOR_TYPES: dict[str, dict[str, Union[str, int]]]= {
    "cert-domain" : {'tier': 1},
    "crypto-wallet" : {'tier': 1},
    "domain" : {'tier': 1},
    "domain_suffix" : {'tier': 1},
    "fb_pixel_id" : {'tier': 1},
    "adobe_analytics_id" : {'tier': 1},
    "sitemap_entries" : {'tier': 3},
    "ipms_domain_iprangeowner_cidr" : {'tier': 3},
    "ipms_domain_iprangeowner_ownerName" : {'tier': 3},
    "ipms_domain_iprangeowner_address" : {'tier': 3},
    "ipms_domain_nameserver" : {'tier': 3},
    "ipms_domain_otheripused" : {'tier': 3},
    "ipms_siteonthisip_now" : {'tier': 3},
    "ipms_siteonthisip_before" : {'tier': 3},
    "ipms_siteonthisip_broken" : {'tier': 3},
    "ipms_useragents" : {'tier': 3},
    "ip_shodan_hostnames" : {'tier': 1},
    "ip_shodan_ports" : {'tier': 3},
    "ip_shodan_vuln" : {'tier': 2},
    "ip_shodan_cpe" : {'tier': 3},
    "ga_id" : {'tier': 1},
    "ga_tag_id" : {'tier': 1},
    "ip" : {'tier': 1},
    "verification_id" : {'tier': 1},
    "yandex_tag_id" : {'tier': 1},
    "subnet" : {'tier': 2},
    "cdn-domain" : {'tier': 3},
    "cms" : {'tier': 3},
    "css_classes" : {'tier': 3},
    "header-nonstd-value" : {'tier': 3},
    "header-server" : {'tier': 3},
    "id_tags" : {'tier': 3},
    "iframe_id_tags" : {'tier': 3},
    "link_href" : {'tier': 3},
    "meta_generic" : {'tier': 3},
    "meta_social" : {'tier': 3},
    "script_src" : {'tier': 3},
    "uuid" : {'tier': 3},
    "whois_creation_date" : {'tier': 3},
    "whois_server" : {'tier': 3},
    "whois-registrar" : {'tier': 3},
    "wp-blocks" : {'tier': 3},
    "wp-categories" : {'tier': 3},
    "wp-pages" : {'tier': 3},
    "wp-posts" : {'tier': 3},
    "wp-tags" : {'tier': 3},
    "wp-users" : {'tier': 3},
    "urlscan_globalvariable": {'tier': 2},
    "urlscan_cookies": {'tier': 2},
    "urlscan_consolemessages": {'tier': 2},
    "urlscan_asn": {'tier': 2},
    "urlscan_domainsonpage": {'tier': 2},
    "urlscan_urlssonpage" : {'tier': 2},
    "urlscanhrefs" : {'tier': 2},
    "techstack" : {'tier': 2},
    "footer-text": {'tier': 3},
    "outbound-domain": {'tier': 4},
    "ads_txt": {'tier': 2},
    "content-title": {"tier": 4},
    "content-link": {"tier": 4},
    "content-summary": {"tier": 4},
    "content-published": {"tier": 4}
}
INDICATOR_TYPES.update(FINANCIAL_IDS)
INDICATOR_TYPES.update(EMBEDDED_IDS)
INDICATOR_TYPES.update(SOCIAL_MEDIA_IDS)
INDICATOR_TYPES.update(TRACKING_IDS)