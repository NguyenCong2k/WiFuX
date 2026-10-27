"""WiFuX Wi-Fi scanner — WiFiScanner, ported from OneShot.

Ported from OneShot (rofl0r -> drygdryg -> kimocoder/OneShot). GPLv3.
Parses `iw dev <iface> scan` into WPS-enabled networks, flags the ones whose
model appears in the vulnerability list, prints a table and lets the user pick
a target. For authorized testing only.

`wcwidth` is used only for CJK-aware column alignment; it is optional here and
falls back to len() so the package has no hard third-party dependency.
"""

import os
import re
import sys
import csv
import subprocess
from typing import Dict

try:
    from wcwidth import wcswidth as _wcswidth
except Exception:  # pragma: no cover - fallback keeps us dependency-free
    def _wcswidth(s):
        return len(s)


class WiFiScanner:
    """docstring for WiFiScanner"""
    def __init__(self, interface, vuln_list=None):
        self.interface = interface
        self.vuln_list = vuln_list

        reports_fname = os.path.dirname(os.path.realpath(__file__)) + '/reports/stored.csv'
        try:
            with open(reports_fname, 'r', newline='', encoding='utf-8', errors='replace') as file:
                csvReader = csv.reader(file, delimiter=';', quoting=csv.QUOTE_ALL)
                # Skip header
                next(csvReader)
                self.stored = []
                for row in csvReader:
                    self.stored.append(
                        (
                            row[1],   # BSSID
                            row[2]    # ESSID
                        )
                    )
        except FileNotFoundError:
            self.stored = []

    def iw_scanner(self) -> Dict[int, dict]:
        """Parsing iw scan results"""
        def handle_network(line, result, networks):
            networks.append(
                    {
                        'Security type': 'Unknown',
                        'WPS': False,
                        'WPS locked': False,
                        'Model': '',
                        'Model number': '',
                        'Device name': ''
                     }
                )
            networks[-1]['BSSID'] = result.group(1).upper()

        def handle_essid(line, result, networks):
            d = result.group(1)
            networks[-1]['ESSID'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')

        def handle_level(line, result, networks):
            networks[-1]['Level'] = int(float(result.group(1)))

        def handle_securityType(line, result, networks):
            sec = networks[-1]['Security type']
            if result.group(1) == 'capability':
                if 'Privacy' in result.group(2):
                    sec = 'WEP'
                else:
                    sec = 'Open'
            elif sec == 'WEP':
                if result.group(1) == 'RSN':
                    sec = 'WPA2'
                elif result.group(1) == 'WPA':
                    sec = 'WPA'
            elif sec == 'WPA':
                if result.group(1) == 'RSN':
                    sec = 'WPA/WPA2'
            elif sec == 'WPA2':
                if result.group(1) == 'WPA':
                    sec = 'WPA/WPA2'
            networks[-1]['Security type'] = sec

        def handle_wps(line, result, networks):
            networks[-1]['WPS'] = result.group(1)

        def handle_wpsLocked(line, result, networks):
            flag = int(result.group(1), 16)
            if flag:
                networks[-1]['WPS locked'] = True

        def handle_model(line, result, networks):
            d = result.group(1)
            networks[-1]['Model'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')

        def handle_modelNumber(line, result, networks):
            d = result.group(1)
            networks[-1]['Model number'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')

        def handle_deviceName(line, result, networks):
            d = result.group(1)
            networks[-1]['Device name'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')

        cmd = 'iw dev {} scan'.format(self.interface)
        proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, encoding='utf-8', errors='replace')
        lines = proc.stdout.splitlines()
        networks = []
        matchers = {
            re.compile(r'BSS (\S+)( )?\(on \w+\)'): handle_network,
            re.compile(r'SSID: (.*)'): handle_essid,
            re.compile(r'signal: ([+-]?([0-9]*[.])?[0-9]+) dBm'): handle_level,
            re.compile(r'(capability): (.+)'): handle_securityType,
            re.compile(r'(RSN):\t [*] Version: (\d+)'): handle_securityType,
            re.compile(r'(WPA):\t [*] Version: (\d+)'): handle_securityType,
            re.compile(r'WPS:\t [*] Version: (([0-9]*[.])?[0-9]+)'): handle_wps,
            re.compile(r' [*] AP setup locked: (0x[0-9]+)'): handle_wpsLocked,
            re.compile(r' [*] Model: (.*)'): handle_model,
            re.compile(r' [*] Model Number: (.*)'): handle_modelNumber,
            re.compile(r' [*] Device name: (.*)'): handle_deviceName
        }

        for line in lines:
            if line.startswith('command failed:'):
                print('[!] Error:', line)
                return False
            line = line.strip('\t')
            for regexp, handler in matchers.items():
                res = re.match(regexp, line)
                if res:
                    handler(line, res, networks)

        # Filtering non-WPS networks
        networks = list(filter(lambda x: bool(x['WPS']), networks))
        if not networks:
            return False

        # Sorting by signal level
        networks.sort(key=lambda x: x['Level'], reverse=True)

        # Putting a list of networks in a dictionary, where each key is a network number in list of networks
        network_list = {(i + 1): network for i, network in enumerate(networks)}

        # Printing scanning results as table
        def truncateStr(s, length, postfix="…"):
            """
            Truncate strings according to display width (supports Full and half width characters)
            :param s: input string
            :param length: Maximum display width (unit: column)
            :param postfix: Truncate suffixes (such as ellipses)
            """
            # Calculate the original display width
            original_width = _wcswidth(s)
            
            # Scenario 1: The original width is exactly the same or smaller
            if original_width <= length:
                # Calculate the number of spaces to be filled (by display width)
                padding_needed = length - original_width
                # Allocate spaces evenly to the right of the string
                return s + ' ' * padding_needed
            
            # Scenario 2: Truncation is required
            postfix_width = _wcswidth(postfix)
            max_allowed = length - postfix_width
            
            current_width = 0
            truncated = []
            for c in s:
                char_width = _wcswidth(c)
                if current_width + char_width > max_allowed:
                    break
                truncated.append(c)
                current_width += char_width
            
            # Construct basic results
            result = "".join(truncated)
            if len(truncated) < len(s):
                result += postfix
            
            # Accurately adjust the display width
            result_width = _wcswidth(result)
            if result_width > length:
                # Remove pre truncation restrictions and switch to more precise truncation
                # Emergency cutoff (to prevent exceeding the limit)
                # Change to character by character processing to ensure not exceeding the limit
                current_width = 0
                safe_truncated = []
                for c in result:
                    char_width = _wcswidth(c)
                    if current_width + char_width > length:
                        break
                    safe_truncated.append(c)
                    current_width += char_width
                safe_result = "".join(safe_truncated)
                # If the truncated string becomes shorter, add ellipsis
                if len(safe_result) < len(result):
                    safe_result += postfix
                    # Recheck the width
                    if _wcswidth(safe_result) > length:
                        # If the limit is still exceeded after adding ellipsis, remove the ellipsis
                        safe_result = safe_result[:-1]
                return safe_result
            
            # Fill in exact spaces
            padding_needed = length - result_width
            return result + ' ' * padding_needed

        def colored(text, color=None):
            """Returns colored text"""
            if color:
                if color == 'green':
                    text = '\033[92m{}\033[00m'.format(text)
                elif color == 'red':
                    text = '\033[91m{}\033[00m'.format(text)
                elif color == 'yellow':
                    text = '\033[93m{}\033[00m'.format(text)
                else:
                    return text
            else:
                return text
            return text

        if self.vuln_list:
            print('Network marks: {1} {0} {2} {0} {3}'.format(
                '|',
                colored('Possibly vulnerable', color='green'),
                colored('WPS locked', color='red'),
                colored('Already stored', color='yellow')
            ))
        print('Networks list:')
        print('{:<4} {:<18} {:<25} {:<8} {:<4} {:<27} {:<}'.format(
            '#', 'BSSID', 'ESSID', 'Sec.', 'PWR', 'WSC device name', 'WSC model'))

        network_list_items = list(network_list.items())
        if args.reverse_scan:
            network_list_items = network_list_items[::-1]
        for n, network in network_list_items:
            number = f'{n})'
            model = '{} {}'.format(network['Model'], network['Model number'])
            essid = truncateStr(network.get('ESSID', 'HIDDEN'), 25)
            deviceName = truncateStr(network['Device name'], 27)
    
            # Processing the display width of other fields
            processed_number = truncateStr(number, 4)
            processed_bssid = truncateStr(network['BSSID'], 18)
            processed_security = truncateStr(network['Security type'], 8)
            processed_level = truncateStr(str(network['Level']), 4)
            processed_device = deviceName  # 27 columns of width have been processed
            processed_model = model  # Assuming that the model fields do not need to be truncated or have been processed
            
            # Directly concatenate the processed fields, separated by spaces in the middle
            line_parts = [
                processed_number,
                processed_bssid,
                essid,
                processed_security,
                processed_level,
                processed_device,
                processed_model
            ]
            line = ' '.join(line_parts)
            
            if (network['BSSID'], network.get('ESSID', 'HIDDEN')) in self.stored:
                print(colored(line, color='yellow'))
            elif network['WPS locked']:
                print(colored(line, color='red'))
            elif self.vuln_list and (model in self.vuln_list):
                print(colored(line, color='green'))
            else:
                print(line)

        return network_list

    def prompt_network(self) -> str:
        networks = self.iw_scanner()
        if not networks:
            print('[-] No WPS networks found.')
            return
        while 1:
            try:
                networkNo = input('Select target (press Enter to refresh): ')
                if networkNo.lower() in ('r', '0', ''):
                    return self.prompt_network()
                elif int(networkNo) in networks.keys():
                    return networks[int(networkNo)]['BSSID']
                else:
                    raise IndexError
            except Exception:
                print('Invalid number')


