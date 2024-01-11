import re


TRACKING_IDS = {
    "1-ga_id": r"(UA-\d{6,}|UA-\d{6,}-\d{1})",
    "1-adsense_id": r"pub-\d{10,20}",
    "1-ga_tag_id": r"(G-([A-Za-z0-9]{6,16})|GTM-[A-Za-z0-9]{6,16}|AW-[A-Za-z0-9]{6,16}|GT-([A-Za-z0-9]{6,16}))",
    "1-adobe_analytics_id": r"s\.account\s*=\s*[\"']([^\"']+)[\"']",
    "1-fb_pixel_id": r"fbq\('init',\s*'(\d+)'\)",
    "1-hotjar_id": r"hjid\s*=\s*(\d+)",
    "1-ms_clarity_id": r"clarity\s*:\s*{.*?projectId\s*:\s*[\"']([^\"']+)[\"']",
    "1-pinterest_tag_id": r"pintrk\('load',\s*'([^']+)'\)",
    "1-linkedin_insight_id": r"linkedin_insight\s*:\s*{.*?partnerId\s*:\s*(\d+)",
    "1-yandex_tag_id": r"ym\(\d{8}",
}

EMBEDDED_IDS = {
    "2-mapbox_public_key": r"pk\.ey[a-zA-Z0-9]{50,90}\.[a-zA-Z0-9\-]{10,30}",
    "1-mapbox_secret_key": r"sk\.ey[a-zA-Z0-9]{50,90}\.[a-zA-Z0-9\-]{10,30}",
}

SOCIAL_MEDIA_IDS = {
    "3-facebook": r"https?://(?:www\.)?facebook\.com/([^/?]+)\b",
    "3-youtube": r"https?://(?:www\.)?youtube\.com/(?:user|channel)/([^/?]+)\b",
    "3-instagram": r"https?://(?:www\.)?instagram\.com/(@?[\w.-]+)\b",
    "3-tiktok": r"https?://(?:www\.)?tiktok\.com/(@?[\w.-]+)\b",
    "3-linkedin": r"https?://(?:www\.)?linkedin\.com/in/([\w-]+)\b",
    "3-telegram": r"https?://(?:www\.)?t\.me/([\w-]+)\b",
    "3-douyin": r"https?://(?:www\.)?douyin\.com/(@?[\w.-]+)\b",
    "3-qq": r"https?://user\.qzone\.qq\.com/(\d+)\b",
    "3-snapchat": r"https?://(?:www\.)?snapchat\.com/add/([\w.-]+)\b",
    "3-pinterest": r"https?://(?:www\.)?pinterest\.com/([^/?]+)\b",
    "3-reddit": r"https?://(?:www\.)?reddit\.com/user/([\w-]+)\b",
    "3-twitter": r"https?://(?:www\.)?twitter\.com/([\w-]+)\b",
    "3-imo": r"https?://(?:www\.)?imo\.im/([\w.-]+)\b",
    "3-line": r"https?://(?:www\.)?line\.me/R/ti/p/([\w.-]+)\b",
    "3-vevo": r"https?://(?:www\.)?vevo\.com/([^/?]+)\b",
    "3-discord": r"https?://(?:www\.)?discord(?:app)?\.com/([\w.-]+)\b",
    "3-twitch": r"https?://(?:www\.)?twitch\.tv/([\w.-]+)\b",
    "3-vk": r"https?://(?:www\.)?vk\.com/([\w.-]+)\b",
    "3-parler": r"https?://(?:www\.)?parler\.com/profile/([\w.-]+)\b",
    "3-gab": r"https?://(?:www\.)?gab\.com/([\w.-]+)\b",
    "3-odysee": r"https?://(?:www\.)?odysee\.com/(@?[\w.-]+)\b",
    "3-lbry": r"https?://(?:www\.)?lbry\.tv/(@?[\w.-]+)\b",
    "3-truthsocial": r"https?://(?:www\.)?truthsocial\.com/user/([\w.-]+)\b",
    "3-bitchute": r"https?://(?:www\.)?bitchute\.com/channel/([\w.-]+)\b",
    "3-gettr": r"https?://(?:www\.)?gettr\.com/user/([\w.-]+)\b",
    "3-rumble": r"https?://(?:www\.)?rumble\.com/([\w.-]+)\b",
    "3-locals": r"https?://(?:www\.)?locals\.com/([\w.-]+)\b",
    "3-applepodcasts": r"https?://(?:podcasts\.apple\.com|itunes\.apple\.com)/([^/?]+)\b",
    "3-iheartradio": r"https?://(?:www\.)?iheart\.com/(?:[^/]+/)?(?:podcast|show)/([\w-]+)\b",
    "3-googleplay": r"https?://play\.google\.com/store/apps/details\?id=([\w.]+)\b"
}