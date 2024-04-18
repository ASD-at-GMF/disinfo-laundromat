TRACKING_IDS = {
    "ga_id": {"pattern": r"(UA-\d{6,}|UA-\d{6,}-\d{1})", "tier": 1},
    "adsense_id": {"pattern": r"pub-\d{10,20}", "tier": 1},
    "ga_tag_id": {"pattern": r"(G-([A-Za-z0-9]{6,16})|GTM-[A-Za-z0-9]{6,16}|AW-[A-Za-z0-9]{6,16}|GT-([A-Za-z0-9]{6,16}))", "tier": 1},
    "adobe_analytics_id": {"pattern": r"s\.account\s*=\s*[\"']([^\"']+)[\"']", "tier": 1},
    "fb_pixel_id": {"pattern": r"fbq\('init',\s*'(\d+)'\)", "tier": 1},
    "hotjar_id": {"pattern": r"hjid\s*=\s*(\d+)", "tier": 1},
    "ms_clarity_id": {"pattern": r"clarity\s*:\s*{.*?projectId\s*:\s*[\"']([^\"']+)[\"']", "tier": 1},
    "pinterest_tag_id": {"pattern": r"pintrk\('load',\s*'([^']+)'\)", "tier": 1},
    "linkedin_insight_id": {"pattern": r"linkedin_insight\s*:\s*{.*?partnerId\s*:\s*(\d+)", "tier": 1},
    "yandex_tag_id": {"pattern": r"ym\(\d{8}", "tier": 1},
    "google_analytics_tags": {"pattern": r"google-analytics\.com\/.*?\?tid=UA-(\d+-\d+)", "tier": 1},
    "scorecard_research_beacon_tags": {"pattern": r"scorecardresearch\.com\/.*?c2=(\d+)", "tier": 1},
    "cloudflare_insights_tags": {"pattern": r"cloudflareinsights\.com\/.*?token=(\w+)", "tier": 1},
    "sentry_tags": {"pattern": r"sentry-cdn\.com\/.*?dsn=(https:\/\/\S+)", "tier": 1},
    "new_relic_tags": {"pattern": r"nr-data\.net\/.*?licenseKey=(\w+)", "tier": 1},
    "yandex_metrika_tags": {"pattern": r"yandex\.ru\/metrika\/.*?id=(\d+)", "tier": 1},
    "chartbeat_tags": {"pattern": r"chartbeat\.com\/.*?uid=(\d+)", "tier": 1},
    "hotjar_tags": {"pattern": r"(hotjar-(\d+))|hjid:(\d+)", "tier": 1},
    "soasta_mpulse_tags": {"pattern": r"akstat\.io\/.*?boomerang=(\w+)", "tier": 1},
    "microsoft_clarity_tags": {"pattern": r"microsoft\.com\/.*?id=(\w+)", "tier": 1},
    "tiktok_analytics_tags": {"pattern": r"tiktok\.com\/.*?aid=(\d+)", "tier": 1},
    "wordpress_stats_tags": {"pattern": r"wp\.com\/.*?\?blog=(\d+)", "tier": 1},
    "adobe_experience_cloud_tags": {"pattern": r"2o7\.net\/.*?mid=(\w+)", "tier": 1},
    "optimizely_tags": {"pattern": r"optimizely\.com\/.*?id=(\d+)", "tier": 1},
    "jetpack_tags": {"pattern": r"jetpack\.com\/.*?blog=(\d+)", "tier": 1},
    "linkedin_analytics_tags": {"pattern": r"https:\/\/px\.ads\.linkedin\.com\/.*?li_fat_id=(\w+)", "tier": 1},
    "amplitude_tags": {"pattern": r"https:\/\/api\.amplitude\.com\/.*?client_id=(\w+)", "tier": 1},
    "mixpanel_tags": {"pattern": r"https:\/\/api\.mixpanel\.com\/.*?distinct_id=(\w+)", "tier": 1},
    "google_tag_manager_tags": {"pattern": r"https:\/\/www\.googletagmanager\.com\/gtm\.js\?.*?id=(GTM-\w+)", "tier": 1},
    "adobe_dynamic_tag_management_tags": {"pattern": r"https:\/\/assets\.adobedtm\.com\/.*?\/(.*?).js", "tier": 1},
    "didomi_tags": {"pattern": r"didomi\.io\/.*?&id=(\w+)", "tier": 1},
    "adobe_typekit_tags": {"pattern": r"https:\/\/use\.typekit\.net\/(.*?).js", "tier": 1},
    "onesignal_tags": {"pattern": r"onesignal\.com\/sdks\/OneSignalSDK\.js\?.*?appId=(\w+)", "tier": 1},
    "piano_tags": {"pattern": r"tinypass\.com\/api\/tinypass\.min\.js\?.*?aid=(\w+)", "tier": 1},
    "forter_tags": {"pattern": r"forter\.com\/.*?/js\/.*?/forter\.js\?.*?siteId=(\w+)", "tier": 1},
    "commanders_act_tags": {"pattern": r"tagcommander\.com\/.*?/tc_(\d+)\.js", "tier": 1},
    "launch_darkly_tags": {"pattern": r"launchdarkly\.com\/sdk\/eval\/.*?\/environments\/(.*?).js", "tier": 1},
    "tealium_tags": {"pattern": r"tiqcdn\.com\/.*?\/utag\.(\d+)\/.*?\/utag\.js", "tier": 1},
    "ensighten_tags": {"pattern": r"ensighten\.com\/.*?\/.*?\/Bootstrap\.js", "tier": 1},
    "impact_radius_tags": {"pattern": r"impactradius-event\.com\/.*?\/ir\.js\?.*?advertiserId=(\w+)", "tier": 1},
    "trusted_shops_tags": {"pattern": r"trustedshops\.com\/reviews\/tsSticker\/tsSticker\.js\?.*?shopId=(\w+)", "tier": 1},
    "dynamic_yield_tags": {"pattern": r"dynamicyield\.com\/api\/\d+\/api_dynamic\.js\?.*?dyid=(\w+)", "tier": 1},
    "truste_seal_tags": {"pattern": r"truste\.com\/privacy-seal\/(.*?)-(.*?)-(.*?)-(.*?)-(.*?)-(.*?).png", "tier": 1},
    "cookie_script_tags": {"pattern": r"cookie-script\.com\/s\/.*?cookie-script\.js\?.*?data-id=(\w+)", "tier": 1},
    "iovation_tags": {"pattern": r"https:\/\/mpsnare\.iesnare\.com\/snare\.js\?.*?org_id=(\w+)", "tier": 1},
    "iab_consent_tags": {"pattern": r"iabtcf\.com\/tcframework\/v2\/tcframework\.min\.js\?.*?cmpId=(\w+)", "tier": 1},
    "evidon_tags": {"pattern": r"evidon\.com\/sitenotice\/(.*?)-(.*?).js", "tier": 1},
    "foresee_tags": {"pattern": r"answerscloud\.com\/(.*?)/gateway\.js", "tier": 1},
    "digicert_trust_seal_tags": {"pattern": r"digicert\.com\/seals\/.*?cjs\?.*?sealid=(\w+)", "tier": 1},
    "mcafee_secure_tags": {"pattern": r"yotpo\.com\/trustedsite\/trustmark\.js\?.*?id=(\w+)", "tier": 1}

}