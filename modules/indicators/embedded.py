EMBEDDED_IDS = {
    "mapbox_public_key": {"pattern": r"pk\.ey[a-zA-Z0-9]{50,90}\.[a-zA-Z0-9\-]{10,30}", "tier": 2},
    "mapbox_secret_key": {"pattern": r"sk\.ey[a-zA-Z0-9]{50,90}\.[a-zA-Z0-9\-]{10,30}", "tier": 1},
    "generic_uuid": {"pattern": r"[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12}", "tier": 3}
}