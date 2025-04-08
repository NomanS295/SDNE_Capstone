-- Create Scan Results Table
CREATE TABLE scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    essid TEXT,
    bssid TEXT,
    channel INTEGER,
    avg_power REAL,
    auth TEXT,
    enc TEXT,
    scanned_at TEXT,
    whitelist_id TEXT
);

-- Create Alerts Table
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    essid TEXT,
    bssid TEXT,
    channel INTEGER,
    avg_power REAL,
    auth TEXT,
    enc TEXT,
    alert_type TEXT,
    detected_at TEXT,
    whitelist_id TEXT
);
