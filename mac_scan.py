#!/usr/bin/env python3
"""
mac_scan.py — Scan this Mac with system_profiler and generate a CMDB import CSV.

Usage:
    python3 mac_scan.py                      # print CSV to stdout
    python3 mac_scan.py -o mac_cis.csv       # write to file
    python3 mac_scan.py -o mac_cis.csv --rel # also write mac_rels.csv

Then upload the CSV(s) at: yoursite.com/impact/import.php
"""

import subprocess
import json
import csv
import sys
import os
import re
import argparse
import getpass
import urllib.request
import urllib.parse
import urllib.error
import io
import mimetypes
from datetime import datetime
from typing import Optional, Tuple

# ── CI type mapping (must match ci_types.php values) ────────────────────────
# Compute: server, mainframe, workstation, laptop, virtual_machine, cluster
# Network: router, switch, firewall, load_balancer, wireless_ap,
#          ip_network, vlan, vpn, ip_address, network_iface
# Storage: storage_device, san, nas, tape_library
# Software: app, web_app, mobile_app, desktop_app, os, middleware,
#           app_server, web_server, message_queue, software_license
# Cloud:   cloud_service, iaas, paas, saas, container
# Other:   service, printer

# APFS synthetic volumes we don't care about as CIs
SKIP_VOLUMES = {'preboot', 'vm', 'update', 'recovery', 'data', 'xarts',
                'hardware', 'imtranslation'}

# Network interface types to skip (loopback, utun tunnels, etc.)
SKIP_IFACE_PREFIXES = ('lo', 'utun', 'llw', 'anpi', 'bridge', 'awdl', 'gif', 'stf')


def run_profiler(data_type: str, timeout: int = 60) -> dict:
    try:
        r = subprocess.run(
            ['system_profiler', data_type, '-json'],
            capture_output=True, text=True, timeout=timeout
        )
        return json.loads(r.stdout) if r.returncode == 0 else {}
    except Exception as e:
        print(f"  ⚠ Could not run system_profiler {data_type}: {e}", file=sys.stderr)
        return {}


def fmt_bytes(n) -> str:
    try:
        n = int(n)
    except (TypeError, ValueError):
        return str(n) if n else ''
    for unit in ['B', 'KB', 'MB', 'GB', 'TB', 'PB']:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} EB"


def build_details(**kwargs) -> str:
    """Build a pipe-separated details string, skipping blank values."""
    parts = []
    for k, v in kwargs.items():
        v = str(v).strip() if v else ''
        if v and v.lower() not in ('unknown', 'none', 'n/a', '(null)'):
            parts.append(f"{k}: {v}")
    return ' | '.join(parts)


def collect_hardware(rows: list) -> str:
    """Collect hardware CIs and return the machine name for relationship building."""
    print("  Scanning hardware…", file=sys.stderr)
    data = run_profiler('SPHardwareDataType').get('SPHardwareDataType', [])
    machine_name = ''
    for hw in data:
        machine_name = hw.get('machine_name', 'This Mac')
        model        = hw.get('machine_model', '')
        chip         = hw.get('cpu_type', hw.get('chip_type', ''))
        memory       = hw.get('physical_memory', '')
        serial       = hw.get('serial_number', hw.get('serial_number_system', ''))
        cores        = hw.get('number_processors', '')

        # MacBooks are laptops, everything else (mini, iMac, Studio, Pro) is a workstation
        ci_type = 'workstation'
        if 'MacBook' in machine_name or 'MacBook' in model:
            ci_type = 'laptop'

        details = build_details(
            Model=model, Chip=chip, Memory=memory, Cores=cores
        )

        rows.append([machine_name, ci_type, details, '', '', serial, 1, 'Apple Inc.', model, ''])
        print(f"    ✓ Hardware: {machine_name} ({model})", file=sys.stderr)

    return machine_name


def collect_os(rows: list, rel_rows: Optional[list], mac_name: str):
    print("  Scanning OS…", file=sys.stderr)
    data = run_profiler('SPSoftwareDataType').get('SPSoftwareDataType', [])
    for sw in data:
        os_version  = sw.get('os_version', '')
        kernel      = sw.get('kernel_version', '')
        hostname    = sw.get('local_host_name', sw.get('computer_name', ''))
        boot_volume = sw.get('boot_volume', '')
        uptime      = sw.get('uptime', '')

        if not os_version:
            continue

        # Name it "macOS 15.3.1" etc.
        name    = os_version.split('(')[0].strip() if os_version else 'macOS'
        # Extract version number robustly — handles "macOS 15.3.1" and "macOS Sequoia 15.3.1"
        version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', name)
        os_ver_num = version_match.group(1) if version_match else ''
        details = build_details(Kernel=kernel, Hostname=hostname,
                                BootVolume=boot_volume, Uptime=uptime)
        rows.append([name, 'os', details, '', '', '', 1, 'Apple Inc.', '', os_ver_num])

        if mac_name and rel_rows is not None:
            rel_rows.append([mac_name, 'Runs', name])

        print(f"    ✓ OS: {name}", file=sys.stderr)


def collect_storage(rows: list, rel_rows: Optional[list], mac_name: str):
    print("  Scanning storage…", file=sys.stderr)
    data = run_profiler('SPStorageDataType').get('SPStorageDataType', [])
    seen = set()

    for vol in data:
        name  = vol.get('_name', '').strip()
        mount = vol.get('mount_point', '')
        # Skip APFS synthetic system volumes (only keep user-visible mounts)
        if not name or name.lower() in SKIP_VOLUMES or name in seen:
            continue
        if mount and mount.startswith('/System/Volumes/') and mount != '/System/Volumes/Data':
            continue
        seen.add(name)

        bsd    = vol.get('bsd_name', '')
        size   = vol.get('size_in_bytes', 0)
        free   = vol.get('free_space_in_bytes', 0)
        fs     = vol.get('file_system', '')

        # Pull physical disk info if available
        phys   = vol.get('physical_drive', {})
        medium = phys.get('medium_type', '')
        smart  = phys.get('smart_status', '')

        details = build_details(
            BSD=bsd, Size=fmt_bytes(size), Free=fmt_bytes(free),
            Mount=mount, FS=fs, Medium=medium, SMART=smart
        )

        rows.append([name, 'storage_device', details, '', '', '', 1, '', '', ''])

        if mac_name and rel_rows is not None:
            rel_rows.append([mac_name, 'Contains', name])

        print(f"    ✓ Volume: {name} ({fmt_bytes(size)})", file=sys.stderr)


def collect_network(rows: list, rel_rows: Optional[list], mac_name: str):
    print("  Scanning network interfaces…", file=sys.stderr)
    data = run_profiler('SPNetworkDataType').get('SPNetworkDataType', [])

    for iface in data:
        name      = iface.get('_name', '').strip()
        interface = iface.get('interface', '')
        if not name:
            continue

        # Skip loopback and virtual tunnel interfaces
        if interface and interface.lower().startswith(SKIP_IFACE_PREFIXES):
            continue

        # MAC address can be in different places depending on interface type
        mac_addr = (iface.get('Ethernet', {}).get('mac_address')
                    or iface.get('hardware_address', '')
                    or iface.get('MAC Address', ''))

        ip4 = iface.get('IPv4', {})
        ip4_addrs = ip4.get('Addresses', [])
        ip4_addr  = ip4_addrs[0] if isinstance(ip4_addrs, list) and ip4_addrs else ''

        ip6 = iface.get('IPv6', {})
        ip6_addrs = ip6.get('Addresses', [])
        ip6_addr  = ip6_addrs[0] if isinstance(ip6_addrs, list) and ip6_addrs else ''

        iface_type = iface.get('type', '')

        # Truncate long IPv6 addresses for readability (fix: parenthesise the conditional)
        ip6_display = (ip6_addr[:24] + '…') if len(ip6_addr) > 24 else ip6_addr

        details = build_details(
            Interface=interface, MAC=mac_addr, IPv4=ip4_addr,
            IPv6=ip6_display,
            Type=iface_type
        )

        # Append the BSD interface name so two adapters of the same type
        # (e.g. two AirPort interfaces: en0 and en1) get unique CI names.
        ci_name = f"{name} ({interface})" if interface else name
        rows.append([ci_name, 'network_iface', details, '', '', '', 1, '', '', ''])

        if mac_name and rel_rows is not None:
            rel_rows.append([mac_name, 'Has', ci_name])

        print(f"    ✓ Interface: {ci_name} ({interface})", file=sys.stderr)


def collect_memory(rows: list, rel_rows: Optional[list], mac_name: str):
    """Only relevant for Intel Macs with individual DIMMs."""
    print("  Scanning memory…", file=sys.stderr)
    data = run_profiler('SPMemoryDataType').get('SPMemoryDataType', [])
    found = 0
    for bank in data:
        items = bank.get('_items', [])
        for slot in items:
            slot_name = slot.get('_name', '').strip()
            size      = slot.get('dimm_size', '').strip()
            mem_type  = slot.get('dimm_type', '').strip()
            speed     = slot.get('dimm_speed', '').strip()
            mfr       = slot.get('dimm_manufacturer', '').strip()
            status    = slot.get('dimm_status', '').strip()

            # Skip empty slots
            if not slot_name or size.lower() in ('', 'empty', '(empty)', '0 mb'):
                continue

            ci_name = f"RAM {slot_name}"
            details = build_details(Size=size, Type=mem_type, Speed=speed,
                                    Manufacturer=mfr, Status=status)
            # Use 'storage_device' since 'memory' isn't in the documented ci_types list
            rows.append([ci_name, 'storage_device', details, '', '', '', 1, mfr, '', ''])
            if mac_name and rel_rows is not None:
                rel_rows.append([mac_name, 'Contains', ci_name])
            found += 1
            print(f"    ✓ DIMM: {ci_name} ({size})", file=sys.stderr)

    if found == 0:
        print("    (Apple Silicon unified memory — no individual DIMMs to import)",
              file=sys.stderr)


def _multipart_body(fields: dict, files: dict) -> Tuple[bytes, str]:
    """Build a multipart/form-data body. files = {field: (filename, data_bytes)}."""
    boundary = b'----CMDBBoundary' + os.urandom(12).hex().encode()
    body = b''
    for name, value in fields.items():
        body += b'--' + boundary + b'\r\n'
        body += f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
        body += str(value).encode() + b'\r\n'
    for name, (filename, data) in files.items():
        mime = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
        body += b'--' + boundary + b'\r\n'
        body += f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode()
        body += f'Content-Type: {mime}\r\n\r\n'.encode()
        body += data + b'\r\n'
    body += b'--' + boundary + b'--\r\n'
    return body, f'multipart/form-data; boundary={boundary.decode()}'


def upload_to_cmdb(base_url: str, username: str, password: str,
                   ci_csv_path: str, rel_csv_path: Optional[str],
                   as_user: Optional[str], catalog_csv_path: Optional[str] = None):
    """Log in to the CMDB and upload CI (and optionally relationship) CSV."""
    base_url = base_url.rstrip('/')
    opener   = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())

    # ── 1. Login ──────────────────────────────────────────────────────────────
    print('\n  Logging in…', file=sys.stderr)
    login_data = urllib.parse.urlencode({
        'username': username,
        'password': password,
    }).encode()
    try:
        resp = opener.open(f'{base_url}/login.php', login_data, timeout=15)
        final_url = resp.geturl()
        login_html = resp.read().decode(errors='replace')
    except urllib.error.URLError as e:
        print(f'  ✗ Login failed: {e}', file=sys.stderr)
        sys.exit(1)

    # Check both that we redirected away from login.php AND that the response
    # doesn't contain login-failure indicators (some servers 200 the login page
    # without redirecting on bad credentials).
    login_failed = (
        'login.php' in final_url
        or 'Invalid' in login_html
        or 'incorrect' in login_html.lower()
        or '<form' in login_html and 'password' in login_html.lower()
    )
    if login_failed:
        print('  ✗ Login failed — check username and password.', file=sys.stderr)
        sys.exit(1)
    print('  ✓ Logged in', file=sys.stderr)

    def do_import(csv_path: str, tab: str):
        filename = os.path.basename(csv_path)
        with open(csv_path, 'rb') as f:
            csv_data = f.read()

        # Stage 1: preview
        fields = {'action': 'preview', 'tab': tab}
        if as_user:
            fields['target_user'] = as_user
        body, ct = _multipart_body(fields, {'import_file': (filename, csv_data)})
        req = urllib.request.Request(f'{base_url}/import.php', data=body,
                                     headers={'Content-Type': ct})
        try:
            resp = opener.open(req, timeout=30)
            html = resp.read().decode(errors='replace')
        except urllib.error.URLError as e:
            print(f'  ✗ Upload failed: {e}', file=sys.stderr)
            return

        # Extract tmp_path and file_ext from hidden inputs
        tmp_match  = re.search(r'name="tmp_path"\s+value="([^"]+)"', html)
        ext_match  = re.search(r'name="file_ext"\s+value="([^"]+)"', html)
        if not tmp_match or not ext_match:
            if 'Session file missing' in html or 'Please select' in html:
                print(f'  ✗ Server rejected the file.', file=sys.stderr)
            else:
                print(f'  ✗ Could not parse preview response — import may have failed.', file=sys.stderr)
            return

        tmp_path = tmp_match.group(1)
        file_ext = ext_match.group(1)

        # Count preview rows
        ok_count  = html.count('badge-ok')
        err_count = html.count('badge-err')
        print(f'    Preview: {ok_count} will import, {err_count} will skip', file=sys.stderr)
        if ok_count == 0:
            print(f'  ✗ Nothing to import.', file=sys.stderr)
            return

        # Stage 2: confirm import
        fields2 = {'action': 'import', 'tab': tab,
                   'tmp_path': tmp_path, 'file_ext': file_ext}
        if as_user:
            fields2['target_user'] = as_user
        body2, ct2 = _multipart_body(fields2, {})
        req2 = urllib.request.Request(f'{base_url}/import.php', data=body2,
                                      headers={'Content-Type': ct2})
        try:
            resp2 = opener.open(req2, timeout=30)
            html2 = resp2.read().decode(errors='replace')
        except urllib.error.URLError as e:
            print(f'  ✗ Import confirm failed: {e}', file=sys.stderr)
            return

        if 'Import Complete' in html2:
            imported = re.search(r'<strong[^>]*>(\d+)</strong>\s+record', html2)
            n = imported.group(1) if imported else '?'
            print(f'  ✓ Imported {n} {tab.upper()} record(s)', file=sys.stderr)
        else:
            print(f'  ✗ Import may have failed — check the CMDB web UI.', file=sys.stderr)

    # ── 2. Import CIs ─────────────────────────────────────────────────────────
    print(f'  Uploading CIs ({os.path.basename(ci_csv_path)})…', file=sys.stderr)
    do_import(ci_csv_path, 'ci')

    # ── 3. Import relationships ───────────────────────────────────────────────
    if rel_csv_path and os.path.exists(rel_csv_path):
        print(f'  Uploading relationships ({os.path.basename(rel_csv_path)})…', file=sys.stderr)
        do_import(rel_csv_path, 'rel')

    # ── 4. Import product catalog ─────────────────────────────────────────────
    if catalog_csv_path and os.path.exists(catalog_csv_path):
        print(f'  Uploading product catalog ({os.path.basename(catalog_csv_path)})…', file=sys.stderr)
        do_import(catalog_csv_path, 'catalog')


def collect_catalog(ci_rows: list) -> list:
    """Build product catalog rows from already-collected hardware/OS CI rows."""
    catalog = []
    seen = set()

    def add(category, ci_type, item, model, manufacturer, version, patch_number):
        key = (manufacturer.lower(), item.lower(), (model or '').lower(), (version or '').lower())
        if key in seen:
            return
        seen.add(key)
        catalog.append([category, ci_type, item, model or '', manufacturer, version or '', patch_number or ''])

    for row in ci_rows:
        name, ci_type, details, _cost, _cost_type, _serial, *_ = row

        if ci_type in ('laptop', 'workstation'):
            # Parse model and chip from details string "Model: X | Chip: Y | ..."
            model = ''
            for part in details.split(' | '):
                if part.startswith('Model:'):
                    model = part.split(':', 1)[1].strip()
                    break
            add('Hardware', ci_type, name, model, 'Apple Inc.', '', '')

        elif ci_type == 'os':
            # name is like "macOS 15.3.1"
            parts = name.split(' ', 1)
            item    = parts[0] if parts else name        # "macOS"
            version = parts[1].strip() if len(parts) > 1 else ''
            # Extract kernel from details "Kernel: Darwin 24.3.0 | ..."
            patch = ''
            for part in details.split(' | '):
                if part.startswith('Kernel:'):
                    patch = part.split(':', 1)[1].strip()
                    break
            add('Software', 'Operating System', item, '', 'Apple Inc.', version, patch)

    return catalog


def write_csv(path, header, rows):
    if path == '-':
        w = csv.writer(sys.stdout)
        w.writerow(header)
        w.writerows(rows)
    else:
        with open(path, 'w', newline='') as f:
            w = csv.writer(f)
            w.writerow(header)
            w.writerows(rows)
        print(f"\n  → Written {len(rows)} rows to {path}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description='Scan this Mac and generate a CMDB CI import CSV',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate CSV only
  python3 mac_scan.py -o mac_cis.csv --rel

  # Scan and upload directly (imports under your own account)
  python3 mac_scan.py --upload --username alice --password s3cr3t

  # Scan and upload under a specific user's account
  python3 mac_scan.py --upload --username alice --password s3cr3t --as-user bob

  # Custom server URL
  python3 mac_scan.py --upload --url https://example.com/impact --username alice --password s3cr3t --as-user bob --rel
"""
    )
    parser.add_argument('-o', '--output', default='-',
                        help='Output CSV file path (default: stdout). Auto-set when --upload is used.')
    parser.add_argument('--rel', action='store_true',
                        help='Also output/upload a relationships CSV (requires -o or --upload)')
    parser.add_argument('--no-memory', action='store_true',
                        help='Skip DIMM memory scan (always skipped on Apple Silicon)')
    parser.add_argument('--no-os', action='store_true',
                        help='Skip macOS CI')
    parser.add_argument('--catalog', action='store_true',
                        help='Also generate a product_catalog CSV (requires -o or --upload)')

    # Upload mode
    upload_grp = parser.add_argument_group('upload options')
    upload_grp.add_argument('--upload', action='store_true',
                            help='Log in and upload directly to the CMDB (no manual file upload needed)')
    upload_grp.add_argument('--url', default='https://www.blackholesurfer.com/impact',
                            help='Base URL of the CMDB (default: https://www.blackholesurfer.com/impact)')
    upload_grp.add_argument('--username', '-u', default='',
                            help='CMDB login username')
    upload_grp.add_argument('--password', '-p', default='',
                            help='CMDB login password (INSECURE — visible in `ps` and shell history; '
                                 'prefer the CMDB_PASSWORD env var or interactive prompt)')
    upload_grp.add_argument('--as-user', dest='as_user', default='',
                            metavar='USERNAME',
                            help='Import CIs under this username instead of your own account '
                                 '(you must be a manager or owner)')
    upload_grp.add_argument('--keep-temp', action='store_true',
                            help='When uploading, keep the auto-generated CSV temp files for inspection')

    args = parser.parse_args()

    # Validate
    if args.upload:
        if not args.username:
            print("Error: --upload requires --username", file=sys.stderr)
            sys.exit(1)
        # Resolve password: CLI flag > env var > interactive prompt
        if not args.password:
            args.password = os.environ.get('CMDB_PASSWORD', '')
        if not args.password:
            try:
                args.password = getpass.getpass(f"Password for {args.username}: ")
            except (KeyboardInterrupt, EOFError):
                print("\nAborted.", file=sys.stderr)
                sys.exit(1)
        if not args.password:
            print("Error: no password provided", file=sys.stderr)
            sys.exit(1)
        # Auto-set output path if not given
        if args.output == '-':
            args.output = '/tmp/mac_cis_upload.csv'
        # Always collect relationships when uploading
        args.rel = True
        args.catalog = True
    elif (args.rel or args.catalog) and args.output == '-':
        print("Error: --rel / --catalog require -o <filename>", file=sys.stderr)
        sys.exit(1)

    ci_rows  = []   # [name, ci_type, details, cost, cost_type, serial_number]
    rel_rows = [] if args.rel else None
    cat_rows = []   # product catalog rows

    print(f"\nBlackHoleSurfer CMDB — Mac Scanner", file=sys.stderr)
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", file=sys.stderr)
    print("-" * 40, file=sys.stderr)

    mac_name = collect_hardware(ci_rows)
    if not args.no_os:
        collect_os(ci_rows, rel_rows, mac_name)
    collect_storage(ci_rows, rel_rows, mac_name)
    collect_network(ci_rows, rel_rows, mac_name)
    if not args.no_memory:
        collect_memory(ci_rows, rel_rows, mac_name)

    print("-" * 40, file=sys.stderr)
    print(f"Total CIs found: {len(ci_rows)}", file=sys.stderr)
    if rel_rows is not None:
        print(f"Total relationships: {len(rel_rows)}", file=sys.stderr)

    # Write CI CSV
    write_csv(args.output, ['name', 'ci_type', 'details', 'cost', 'cost_type', 'serial_number', 'is_discovered', 'manufacturer', 'model', 'version'], ci_rows)

    # Write relationships CSV
    rel_path = None
    if rel_rows is not None:
        rel_path = args.output.replace('.csv', '_rels.csv')
        write_csv(rel_path, ['source_name', 'rel_type', 'target_name'], rel_rows)

    # Write product catalog CSV
    cat_path = None
    if args.catalog:
        cat_rows = collect_catalog(ci_rows)
        cat_path = args.output.replace('.csv', '_catalog.csv')
        write_csv(cat_path, ['category', 'type', 'item', 'model', 'manufacturer', 'version', 'patch_number'], cat_rows)
        print(f"  Total catalog entries: {len(cat_rows)}", file=sys.stderr)

    if args.upload:
        print(f"\nUploading to {args.url}…", file=sys.stderr)
        if args.as_user:
            print(f"  Importing under user: {args.as_user}", file=sys.stderr)
        upload_to_cmdb(
            base_url          = args.url,
            username          = args.username,
            password          = args.password,
            ci_csv_path       = args.output,
            rel_csv_path      = rel_path,
            as_user           = args.as_user or None,
            catalog_csv_path  = cat_path,
        )

        # Clean up temp files if we auto-created them (unless --keep-temp)
        auto_temp = (args.output == '/tmp/mac_cis_upload.csv')
        if auto_temp and not args.keep_temp:
            for p in (args.output, rel_path, cat_path):
                if not p:
                    continue
                try:
                    os.unlink(p)
                except OSError:
                    pass
        elif auto_temp and args.keep_temp:
            print(f"\n  Temp files kept:", file=sys.stderr)
            for p in (args.output, rel_path, cat_path):
                if p and os.path.exists(p):
                    print(f"    {p}", file=sys.stderr)
    else:
        print(f"\nUpload at: {args.url.rstrip('/')}/import.php", file=sys.stderr)


if __name__ == '__main__':
    main()
