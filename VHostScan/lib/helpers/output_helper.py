import itertools
import json
import time
import numpy as np

from fuzzywuzzy import fuzz

from ..core.discovered_host import *
from .file_helper import *


class output_helper(object):
    def __init__(self, scanner, arguments):
        self.scanner = scanner
        self.arguments = arguments

    def write_normal(self, filename):
        file = file_helper(filename)

        output = self.generate_header()
        output += self.output_normal_likely()

        if(self.arguments.fuzzy_logic):
            output += self.output_fuzzy()

        output += self.output_normal_detail()
        file.write_file(output)

    def write_grepable(self, filename):
        file = file_helper(filename)

        output = self.generate_header()
        output += self.output_grepable_detail()

        file.write_file(output)

    def output_normal_likely(self):
        uniques = False
        depth = str(self.scanner.unique_depth)
        output = f"\n[+] Most likely matches with a unique count of {depth} or less:"

        for p in self.scanner.likely_matches():
            output += f"\n\t[>] {p}"
            uniques = True

        if uniques:
            return output
        else:
            return f"\n[!] No matches with an unique count of {depth} or less."

    def output_json(self, filename):
        file = file_helper(filename)
        output = {
            'Target': self.scanner.target,
            'Base Host': self.scanner.base_host,
            'Port': self.scanner.port,
            'Real Port': self.scanner.real_port,
            'Ignore HTTP Codes': self.scanner.ignore_http_codes,
            'Ignore Content Length': self.scanner.ignore_content_length,
            'Wordlist': self.scanner.wordlist,
            'Unique Depth': self.scanner.unique_depth,
            'SSL': self.scanner.ssl,
            'Start Time': f'{time.strftime("%d/%m/%Y")} {time.strftime("%H:%M:%S")}',
        }

        result = {}
        for host in self.scanner.hosts:
            headers = {
                header.split(':')[0]: header.split(':')[1].strip()
                for header in host.keys
            }

            result[host.hostname] = {
                'Code': host.response_code,
                'Hash': host.hash,
                'Headers': headers
            }

        output['Result'] = result

        file.write_file(json.dumps(output, indent=2))

    def output_fuzzy(self):
        output = "\n\n[+] Match similarity using fuzzy logic:"
        request_hashes = {host.hostname: host.content for host in self.scanner.hosts}

        for a, b in itertools.combinations(request_hashes.keys(), 2):
            output += f"\n\t[>] {a} is {fuzz.ratio(request_hashes[a], request_hashes[b])}% similar to {b}"


        return output

    def output_normal_detail(self):
        output = "\n\n[+] Full scan results"

        for host in self.scanner.hosts:
            output += f"\n\n{str(host.hostname)} (Code: {str(host.response_code)}) hash: {str(host.hash)}"


            for key in host.keys:
                output += f"\n\t{key}"

        return output

    def output_grepable_detail(self):
        for host in self.scanner.hosts:
            output += f"\n{str(host.hostname)}\t{str(host.response_code)}\t{str(host.hash)}"


        return output

    def generate_header(self):
        output = f'VHostScanner Log: {time.strftime("%d/%m/%Y")} {time.strftime("%H:%M:%S")}\n'


        output += f"\tTarget: {self.scanner.target}\n\tBase Host: {self.scanner.base_host}\n\tPort: {self.scanner.port}"


        output += f"\n\tReal Port {self.scanner.real_port}\n\tIgnore HTTP Codes: {self.scanner.ignore_http_codes}"


        output += f"\n\tIgnore Content Length: {self.scanner.ignore_content_length}\n\tWordlist: {self.scanner.wordlist}"


        output += f"\n\tUnique Depth: {self.scanner.unique_depth}\n\tSSL: {self.scanner.ssl}\n\t"


        return output
