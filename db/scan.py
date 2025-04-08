#!/usr/bin/env python3

import json
import os
import argparse
import time
import struct
import threading
import sqlite3
from datetime import datetime
from scapy.all import *

ap_data = {}
json_file = "scan_results.json"
alert_file = "alert.json"
alerts = []

# ======================= DB Insert Functions =======================
def insert_scan_result(essid, bssid, channel, avg_power, auth, enc, whitelist_id):
    conn = sqlite3.connect('/home/noman/RAP_Scanner/wifi_scanner.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scan_results (essid, bssid, channel, avg_power, auth, enc, scanned_at, whitelist_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (essid, bssid, channel, avg_power, auth, enc, datetime.now().isoformat(), whitelist_id))
    conn.commit()
    conn.close()

def insert_alert(essid, bssid, channel, avg_power, auth, enc, alert_type, whitelist_id):
    conn = sqlite3.connect('/home/noman/RAP_Scanner/wifi_scanner.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO alerts (essid, bssid, channel, avg_power, auth, enc, alert_type, detected_at, whitelist_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (essid, bssid, channel, avg_power, auth, enc, alert_type, datetime.now().isoformat(), whitelist_id))
    conn.commit()
    conn.close()

# ======================= JSON Save Functions =======================
def save_to_json():
    with open(json_file, "w") as f:
        json.dump(ap_data, f, indent=4)

def save_alert_data():
    with open(alert_file, "w") as f:
        json.dump(alerts, f, indent=4)

def start_auto_saving(interval=1):
    def autosave():
        while True:
            save_to_json()
            save_alert_data()
            time.sleep(interval)
    thread = threading.Thread(target=autosave, daemon=True)
    thread.start()

# ======================= Parsing RSN Function =======================
def parse_rsn(rsn_ie):
    try:
        version = struct.unpack("<H", rsn_ie[0:2])[0]
        if version != 1:
            return {}
        group_cipher = rsn_ie[2:6]
        pairwise_count = struct.unpack("<H", rsn_ie[6:8])[0]
        akm_count_offset = 8 + pairwise_count * 4
        akm_count = struct.unpack("<H", rsn_ie[akm_count_offset:akm_count_offset+2])[0]
        akm_suite = rsn_ie[akm_count_offset+2:akm_count_offset+6]
        cipher_map = {1:"WEP-40", 2:"TKIP", 4:"CCMP", 5:"WEP-104"}
        akm_map = {1:"802.1X", 2:"PSK"}
        cipher = cipher_map.get(group_cipher[3], "Unknown")
        auth = akm_map.get(akm_suite[3], "Unknown")
        return {"enc": "WPA2", "cipher": cipher, "auth": auth, "pmf_capable": False, "pmf_required": False}
    except:
        return {}

# ======================= Packet Handling =======================
def packet_handler(pkt, verbose, whitelist, live_alerts_only):
    if pkt.haslayer(Dot11Beacon):
        bssid = pkt[Dot11].addr2
        ssid = pkt[Dot11Elt].info.decode(errors="ignore").strip() or "<Hidden>"
        signal_strength = pkt.dBm_AntSignal if hasattr(pkt, "dBm_AntSignal") else 0
        channel = None
        encryption = "OPN"
        auth = ""
        cipher = ""
        pmf_str = "No"

        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 3:
                channel = elt.info[0]
            elif elt.ID == 48:
                rsn_info = parse_rsn(elt.info)
                encryption = rsn_info.get("enc", "OPN")
                cipher = rsn_info.get("cipher", "")
                auth = rsn_info.get("auth", "")
            elt = elt.payload.getlayer(Dot11Elt)

        if bssid not in ap_data:
            ap_data[bssid] = {
                "essid": ssid,
                "bssid": bssid,
                "pwr": [signal_strength],
                "beacons": 1,
                "data": 0,
                "channel": [channel] if channel else [],
                "mb": "N/A",
                "enc": encryption,
                "cipher": cipher,
                "auth": auth,
                "pmf": pmf_str
            }

            matched_whitelist_id = None
            for entry in whitelist:
                try:
                    entry_essid, entry_bssid = entry.split(',')
                    if (ssid == entry_essid and bssid == entry_bssid) or (ssid == "<Hidden>" and bssid == entry_bssid):
                        matched_whitelist_id = f"{entry_essid},{entry_bssid}"
                        break
                except ValueError:
                    continue

            insert_scan_result(ssid, bssid, channel or 0, signal_strength or 0, auth, encryption, matched_whitelist_id)

        else:
            ap_data[bssid]["beacons"] += 1
            if signal_strength not in ap_data[bssid]["pwr"]:
                ap_data[bssid]["pwr"].append(signal_strength)
            if channel and channel not in ap_data[bssid]["channel"]:
                ap_data[bssid]["channel"].append(channel)

        whitelisted = False
        matched_whitelist_id = None
        for entry in whitelist:
            try:
                entry_essid, entry_bssid = entry.split(',')
                if (ssid == entry_essid and bssid == entry_bssid) or (ssid == "<Hidden>" and bssid == entry_bssid):
                    whitelisted = True
                    matched_whitelist_id = f"{entry_essid},{entry_bssid}"
                    break
            except ValueError:
                continue

        if not whitelisted:
            if not any(alert.get('bssid') == bssid for alert in alerts):
                alert_data = ap_data[bssid].copy()
                alert_data["alert_type"] = "Not Whitelisted"
                alerts.append(alert_data)
                insert_alert(ssid, bssid, channel or 0, signal_strength or 0, auth, encryption, "Not Whitelisted", matched_whitelist_id)

# ======================= Display Functions =======================
def print_ap_data_table(ap_data):
    print("="*120)
    print(f"{'BSSID':<20}{'Avg PWR':<10}{'Beacons':<10}{'#Data':<10}{'CH':<5}{'ENC':<6}{'CIPHER':<8}{'AUTH':<8}{'ESSID'}")
    print("="*120)
    for bssid, data in ap_data.items():
        avg_pwr = sum(data['pwr']) / len(data['pwr']) if data['pwr'] else 0
        ch = ','.join(map(str, data['channel'])) if data['channel'] else "N/A"
        print(f"{bssid:<20}{avg_pwr:<10.1f}{data['beacons']:<10}{data['data']:<10}{ch:<5}{data['enc']:<6}{data['cipher']:<8}{data['auth']:<8}{data['essid']}")
    print("="*120)

def print_alerts_table(alerts):
    print("="*140)
    print(f"{'BSSID':<20}{'Avg PWR':<10}{'Beacons':<10}{'#Data':<10}{'CH':<5}{'ENC':<6}{'CIPHER':<8}{'AUTH':<8}{'ESSID':<20}{'ALERT'}")
    print("="*140)
    for alert in alerts:
        avg_pwr = sum(alert['pwr']) / len(alert['pwr']) if alert.get('pwr') else 0
        ch = ','.join(map(str, alert['channel'])) if alert.get('channel') else "N/A"
        print(f"{alert['bssid']:<20}{avg_pwr:<10.1f}{alert['beacons']:<10}{alert['data']:<10}{ch:<5}{alert['enc']:<6}{alert['cipher']:<8}{alert['auth']:<8}{alert['essid']:<20}{alert['alert_type']}")
    print("="*140)

# ======================= Main =======================
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("iface")
    parser.add_argument("-c", "--channel", type=int)
    parser.add_argument("-d", "--duration", type=int, default=60)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-w", "--whitelist")
    parser.add_argument("-L", "--live-updates", action="store_true")
    parser.add_argument("-A", "--live-alerts-only", action="store_true")
    args = parser.parse_args()

    whitelist = []
    if args.whitelist and os.path.isfile(args.whitelist):
        with open(args.whitelist) as f:
            whitelist = [line.strip() for line in f]

    if args.channel:
        os.system(f"iw dev {args.iface} set channel {args.channel}")

    start_auto_saving()
    start = time.time()

    while time.time() - start < args.duration:
        sniff(iface=args.iface, prn=lambda pkt: packet_handler(pkt, args.verbose, whitelist, args.live_alerts_only), store=False, timeout=1)

        if args.live_updates:
            os.system("clear")
            print_ap_data_table(ap_data)
            print_alerts_table(alerts)

    print("Scan complete!")
    print_ap_data_table(ap_data)
    print_alerts_table(alerts)
    save_to_json()
    save_alert_data()

if __name__ == "__main__":
    main()