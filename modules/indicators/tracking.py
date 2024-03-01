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