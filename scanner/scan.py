#!/usr/bin/env python3

import json
import os
import argparse
import time
import struct
import threading
from scapy.all import *

# This dictionary stores all the Access Point (AP) info, using the BSSID as the key.
# For each AP we record details like ESSID, signal power values, beacon counts, data frame counts,
# channel numbers, maximum bit rate, encryption type, cipher, authentication method, and PMF status.
ap_data = {}
json_file = "scan_results.json"   # File to save the full scan results in JSON format
alert_file = "alert.json"         # File to save alerts for rogue or unwhitelisted APs

# List to keep track of alerts. Each alert is a copy of an AP's data with an extra "alert_type" field.
alerts = []

def save_to_json():
    """Dump the current AP data into a JSON file for later review."""
    with open(json_file, "w") as f:
        json.dump(ap_data, f, indent=4)

def start_auto_saving(interval=1):
    """Continuously save AP data to JSON every `interval` seconds."""
    def autosave():
        while True:
            save_to_json()
            save_alert_data()
            time.sleep(interval)
    thread = threading.Thread(target=autosave, daemon=True)
    thread.start()

def save_alert_data():
    """Dump all alerts into a JSON file for later review."""
    with open(alert_file, "w") as f:
        json.dump(alerts, f, indent=4)

def load_whitelist(file_path):
    """Load whitelist entries from a file, one per line in the format 'ESSID,BSSID'."""
    whitelist = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    whitelist.append(line)
    except Exception as e:
        print(f"Error reading whitelist file: {e}")
    return whitelist


def parse_rsn(rsn_ie):
    """
    Parse the RSN Information Element (IE) found in beacon frames (ID 48).
    This function extracts and returns a dictionary with encryption info:
      - enc: Encryption protocol (e.g., WPA2)
      - cipher: Cipher used (e.g., CCMP)
      - auth: Authentication method (e.g., PSK)
      - pmf_capable: Whether the AP supports Protected Management Frames
      - pmf_required: Whether PMF is required
    """
    try:
        # The first two bytes represent the RSN version
        version = struct.unpack("<H", rsn_ie[0:2])[0]
        if version != 1:
            return {}
        # Next 4 bytes are the group cipher suite
        group_cipher = rsn_ie[2:6]
        # Get the number of pairwise cipher suites
        pairwise_count = struct.unpack("<H", rsn_ie[6:8])[0]
        pairwise_list_length = pairwise_count * 4
        # Extract the first pairwise cipher suite (we use only one for our purpose)
        pairwise_cipher = rsn_ie[8:12]
        # Calculate offset for AKM (authentication) suites
        akm_count_offset = 8 + pairwise_list_length
        akm_count = struct.unpack("<H", rsn_ie[akm_count_offset:akm_count_offset+2])[0]
        akm_list_length = akm_count * 4
        # Get the first AKM suite from the list
        akm_suite = rsn_ie[akm_count_offset+2:akm_count_offset+6]
        # Check if RSN Capabilities (optional 2 bytes) are present
        rsn_capabilities = None
        expected_length_without_cap = akm_count_offset + 2 + akm_list_length
        if len(rsn_ie) >= expected_length_without_cap + 2:
            rsn_capabilities = struct.unpack("<H", rsn_ie[expected_length_without_cap:expected_length_without_cap+2])[0]
        pmf_capable = False
        pmf_required = False
        # Bit 6 indicates PMF capability; bit 7 indicates PMF requirement.
        if rsn_capabilities is not None:
            if rsn_capabilities & 0x0040:
                pmf_capable = True
            if rsn_capabilities & 0x0080:
                pmf_required = True
        # Mapping values for the cipher and authentication suites
        cipher_map = {1:"WEP-40", 2:"TKIP", 4:"CCMP", 5:"WEP-104"}
        akm_map = {1:"802.1X", 2:"PSK"}
        enc = "WPA2"
        cipher = cipher_map.get(pairwise_cipher[3], "Unknown")
        auth = akm_map.get(akm_suite[3], "Unknown")
        return {"enc": enc, "cipher": cipher, "auth": auth, "pmf_capable": pmf_capable, "pmf_required": pmf_required}
    except Exception:
        # In case of any parsing error, return an empty dictionary.
        return {}

def packet_handler(pkt, verbose, whitelist, live_alerts_only):
    """Process each sniffed packet to extract and update AP data."""
    if pkt.haslayer(Dot11Beacon):  # Handling beacon frames
        bssid = pkt[Dot11].addr2  # The BSSID is in the addr2 field
        raw_ssid = pkt[Dot11Elt].info.decode(errors="ignore").strip()  # Extract the SSID safely
        ssid = raw_ssid if raw_ssid else "<Hidden>"  # Mark hidden networks
        display_essid = ssid
        signal_strength = pkt.dBm_AntSignal if hasattr(pkt, "dBm_AntSignal") else None
        encryption = "OPN"  # Default assumption: network is open
        auth = ""
        cipher = ""
        pmf_str = "No"  # Default PMF info
        channel = None
        supported_rates = []
        extended_rates = []
        rsn_ie = None

        # Iterate through the 802.11 elements (IEs) in the beacon frame to gather info.
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0:  # SSID element; already handled above.
                pass
            elif elt.ID == 1:  # Supported Rates element
                supported_rates += list(elt.info)
            elif elt.ID == 50:  # Extended Supported Rates element
                extended_rates += list(elt.info)
            elif elt.ID == 3:  # DS Parameter Set which contains the channel info
                channel = elt.info[0]
            elif elt.ID == 48:  # RSN IE element for WPA2 details
                rsn_ie = elt.info
            elt = elt.payload.getlayer(Dot11Elt)

        # If channel info wasn't found in the loop, try another method.
        if channel is None:
            channel = pkt[Dot11Elt].channel

        # Determine the maximum bit rate from the supported and extended rates.
        all_rates = supported_rates + extended_rates
        if all_rates:
            rates_mbps = [rate * 0.5 for rate in all_rates]
            mb = max(rates_mbps)
        else:
            mb = "N/A"

        # Parse RSN IE if present to get encryption details.
        if rsn_ie:
            rsn_info = parse_rsn(rsn_ie)
            if rsn_info:
                encryption = rsn_info.get("enc", "WPA2")
                cipher = rsn_info.get("cipher", "CCMP")
                auth = rsn_info.get("auth", "PSK")
                if rsn_info.get("pmf_required"):
                    pmf_str = "Required"
                elif rsn_info.get("pmf_capable"):
                    pmf_str = "Capable"
                else:
                    pmf_str = "No"
            else:
                # Fallback values if RSN parsing fails.
                encryption = "WPA2"
                cipher = "CCMP"
                auth = "PSK"
        else:
            # If there’s no RSN IE, then the network is likely open.
            encryption = "OPN"
            cipher = ""
            auth = ""
            pmf_str = "No"

        # Update the global AP data with this beacon's info.
        if bssid not in ap_data:
            # New AP found; create a new record.
            ap_data[bssid] = {
                "essid": display_essid,
                "bssid": bssid,
                "pwr": [signal_strength] if signal_strength is not None else [],
                "beacons": 1,
                "data": 0,
                "channel": [channel] if channel is not None else [],
                "mb": mb,
                "enc": encryption,
                "cipher": cipher,
                "auth": auth,
                "pmf": pmf_str
            }
        else:
            # Existing AP; update counts and append new info if applicable.
            ap_data[bssid]["beacons"] += 1
            if signal_strength is not None and signal_strength not in ap_data[bssid]["pwr"]:
                ap_data[bssid]["pwr"].append(signal_strength)
            if channel is not None and channel not in ap_data[bssid]["channel"]:
                ap_data[bssid]["channel"].append(channel)

        # Check against the whitelist (expected format: "ESSID,BSSID").
        whitelisted = False
        for entry in whitelist:
            try:
                entry_essid, entry_bssid = entry.split(',')
            except ValueError:
                continue  # Skip this entry if it’s not correctly formatted.
            if ssid == entry_essid and bssid == entry_bssid:
                whitelisted = True
                break

        if not whitelisted:
            # For non-whitelisted networks, check for an "evil twin" scenario (same ESSID, different BSSID).
            if ssid != "<Hidden>":  # Only if the network isn’t hidden
                for known_bssid, known_data in ap_data.items():
                    if known_data["essid"] == display_essid and known_bssid != bssid:
                        # Evil twin alert.
                        if not any(alert.get('bssid') == bssid for alert in alerts):
                            alert_data = ap_data[bssid].copy()
                            alert_data["alert_type"] = "Evil Twin Detected"
                            alerts.append(alert_data)
                        if live_alerts_only:
                            print(f"[Evil Twin ALERT] ESSID: {display_essid} BSSID: {bssid} Signal: {signal_strength} Channel: {channel}")
                            print(f"Another BSSID for ESSID {display_essid} detected: {known_bssid}")
            # Create an alert for a network that isn’t whitelisted.
            if not any(alert.get('bssid') == bssid for alert in alerts):
                alert_data = ap_data[bssid].copy()
                alert_data["alert_type"] = "Not Whitelisted"
                alerts.append(alert_data)

        # If verbose mode is on, print out detailed information about this beacon.
        if verbose:
            print(f"[Verbose] Processing Beacon from BSSID: {bssid}, ESSID: {display_essid}, Signal: {signal_strength}, Channel: {channel}")
            print(f"[Verbose] Encryption: {encryption}, Cipher: {cipher}, Auth: {auth}, PMF: {pmf_str}")
            print(f"[Verbose] Max Bit Rate: {mb}, Supported Rates: {supported_rates}")
            print(f"[Verbose] RSN IE: {rsn_ie if rsn_ie else 'None'}")

    elif pkt.haslayer(Dot11) and pkt[Dot11].type == 2:
        # For data frames, count them for the associated AP.
        bssid_data = pkt[Dot11].addr3
        if bssid_data in ap_data:
            ap_data[bssid_data]["data"] += 1

def print_ap_data_table(ap_data, title="All Detected Access Points"):
    """
    Nicely print the collected AP data in a table format.
    Columns include: BSSID, average signal power, beacon count, data count, channel(s), max bit rate,
    encryption type, cipher, auth method, PMF info, and ESSID.
    """
    print("=" * 120)
    print(title)
    print("=" * 120)
    header = f"{'BSSID':<20}{'Avg PWR':<10}{'Beacons':<10}{'#Data':<10}{'CH':<5}{'MB':<6}{'ENC':<6}{'CIPHER':<8}{'AUTH':<8}{'PMF':<10}{'ESSID'}"
    print(header)
    print("=" * 120)
    for bssid, data in ap_data.items():
        # Calculate the average power if we have recorded signal strengths.
        if data["pwr"]:
            avg_pwr = sum(data["pwr"]) / len(data["pwr"])
        else:
            avg_pwr = None
        avg_pwr_str = f"{avg_pwr:.1f}" if avg_pwr is not None else "N/A"
        ch = ','.join(map(str, data["channel"])) if data["channel"] else "N/A"
        print(f"{data['bssid']:<20}{avg_pwr_str:<10}{data['beacons']:<10}{data['data']:<10}{ch:<5}{data['mb']:<6}{data['enc']:<6}{data['cipher']:<8}{data['auth']:<8}{data['pmf']:<10}{data['essid']}")
    print("=" * 120)

def print_alerts_table(alerts, title="Alerts"):
    """
    Nicely print the alerts in a table format.
    Similar columns to the AP table, but with an extra column showing the type of alert.
    """
    print("=" * 140)
    print(title)
    print("=" * 140)
    header = f"{'BSSID':<20}{'Avg PWR':<10}{'Beacons':<10}{'#Data':<10}{'CH':<5}{'MB':<6}{'ENC':<6}{'CIPHER':<8}{'AUTH':<8}{'PMF':<10}{'ESSID':<20}{'Alert'}"
    print(header)
    print("=" * 140)
    for alert in alerts:
        if alert.get("pwr"):
            avg_pwr = sum(alert["pwr"]) / len(alert["pwr"])
            avg_pwr_str = f"{avg_pwr:.1f}"
        else:
            avg_pwr_str = "N/A"
        ch = ','.join(map(str, alert["channel"])) if alert.get("channel") else "N/A"
        alert_type = alert.get("alert_type", "")
        print(f"{alert['bssid']:<20}{avg_pwr_str:<10}{alert['beacons']:<10}{alert['data']:<10}{ch:<5}{alert['mb']:<6}{alert['enc']:<6}{alert['cipher']:<8}{alert['auth']:<8}{alert['pmf']:<10}{alert['essid']:<20}{alert_type}")
    print("=" * 140)

def main():
    # If the user asks for help, display fancy ASCII art along with usage details.
    if '-h' in sys.argv or '--help' in sys.argv:
        print(r"""
                ▗▄▄▖  ▗▄▖ ▗▄▄▖      ▗▄▄▖ ▗▄▄▖ ▗▄▖ ▗▖  ▗▖▗▖  ▗▖▗▄▄▄▖▗▄▄▖ 
                ▐▌ ▐▌▐▌ ▐▌▐▌ ▐▌    ▐▌   ▐▌   ▐▌ ▐▌▐▛▚▖▐▌▐▛▚▖▐▌▐▌   ▐▌ ▐▌
                ▐▛▀▚▖▐▛▀▜▌▐▛▀▘      ▝▀▚▖▐▌   ▐▛▀▜▌▐▌ ▝▜▌▐▌ ▝▜▌▐▛▀▀▘▐▛▀▚▖
                ▐▌ ▐▌▐▌ ▐▌▐▌       ▗▄▄▞▘▝▚▄▄▖▐▌ ▐▌▐▌  ▐▌▐▌  ▐▌▐▙▄▄▖▐▌ ▐▌
                
                """)

    # Set up our command line arguments
    parser = argparse.ArgumentParser(
        usage="%(prog)s [-h Help] iface [-c CHANNEL] [-d DURATION] [-v Verbose] [-w WHITELIST] [-L Live Output] [-A Live Alerts]",
        description="Wi-Fi network scanner that captures and analyzes Wi-Fi networks. "
                    "It supports filtering by whitelist (using ESSID and BSSID), logging detected networks, "
                    "and displaying live updates and alerts. PMF support (Protected Management Frames) is detected "
                    "via the RSN IE.",
        epilog="Examples:\n"
               "  python scan.py wlan0 -c 6 -d 120 -v\n"
               "    Scan for 120 seconds on channel 6 with verbose output.\n"
               "  python scan.py wlan0 -w whitelist.txt\n"
               "    Scan using a whitelist from the specified file (with lines formatted as ESSID,BSSID).\n"
               "  python scan.py wlan0 -L -A\n"
               "    Show live updates with only live alerts (no full AP table)."
    )

    # Define the required and optional parameters
    parser.add_argument("iface", help="Network interface to use (e.g., wlan0, mon0)")
    parser.add_argument("-c", "--channel", type=int, help="Channel to set for scanning")
    parser.add_argument("-d", "--duration", type=int, default=60, help="Duration for scanning in seconds")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-w", "--whitelist", help="File containing whitelist entries (ESSID,BSSID per line)")
    parser.add_argument("-L", "--live-updates", action="store_true", help="Enable live update display")
    parser.add_argument("-A", "--live-alerts-only", action="store_true", help="Enable live alert printing only (print only alerts during live updates)")

    args = parser.parse_args()

    # Load the whitelist if provided, otherwise set it to an empty set for no filtering.
    if args.whitelist:
        if os.path.exists(args.whitelist):
            whitelist = load_whitelist(args.whitelist)
        else:
            # If a file doesn't exist, check if comma-separated list was given.
            whitelist = set(args.whitelist.split(","))
            print(f"Using whitelist from argument: {whitelist}")
    else:
        print("No whitelist provided, proceeding with no filtering.")
        whitelist = set()

    # Set the Wi-Fi channel if the user specified one.
    if args.channel:
        print(f"Setting channel {args.channel}")
        os.system(f"iw dev {args.iface} set channel {args.channel}")

    print(f"Scanning on interface {args.iface}...\n")
    start_time = time.time()
    # Adjust the timeout for each sniffing session based on whether live updates/alerts are showing.
    update_timeout = 1 if args.live_updates or args.live_alerts_only else 5

    # Start background thread to auto-save AP data every 1 second
    start_auto_saving()

    # Keep scanning for the specified duration 
    while time.time() - start_time < args.duration:
        sniff(iface=args.iface,
              prn=lambda pkt: packet_handler(pkt, args.verbose, whitelist, args.live_alerts_only),
              store=False,
              timeout=update_timeout)
        save_to_json()  # Save the current scan results periodically
        save_alert_data() # Save the current alert results periodically

        if args.live_updates:
            os.system("clear")  # Clear the terminal screen for a fresh display
            print_ap_data_table(ap_data)
            print_alerts_table(alerts)

        if args.live_alerts_only:
            os.system("clear")
            print_alerts_table(alerts)
       
    # After scanning, if live updates argument, show a final summary and save all data.
    if not args.live_updates and not args.live_alerts_only:
        print("\nScan complete.\n")
        save_to_json()  # Final save of scan data
        print_ap_data_table(ap_data)
        print_alerts_table(alerts)
        save_alert_data()

    save_alert_data() # Final save of alert data
    save_to_json()  # Final save of scan data

if __name__ == "__main__":
    main()