CREATE TABLE IF NOT EXISTS content_queries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title_query TEXT,
    content_query TEXT,
    combine_operator TEXT
);

CREATE TABLE IF NOT EXISTS sites_base (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT,
    source TEXT
);

CREATE TABLE IF NOT EXISTS sites_user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT,
    source TEXT
);

CREATE TABLE IF NOT EXISTS site_fingerprint (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT,
    indicator TEXT,
    indicator_value TEXT
);
