#!/usr/bin/python3
"""
    Copyright (c) 2024 Penterep Security s.r.o.

    ptresheaders - Response Header Parser

    ptresheaders is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    ptresheaders is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with ptresheaders.  If not, see <https://www.gnu.org/licenses/>.
"""


import argparse
import os
import sys; sys.path.append(__file__.rsplit("/", 1)[0])
import re
import urllib

import requests

from _version import __version__
from ptlibs import ptjsonlib, ptprinthelper, ptmisclib, ptnethelper

from ptlibs.ptprinthelper import ptprint, out_if

from modules.headers import content_security_policy, strict_transport_security, x_frame_options, x_content_type_options, referrer_policy, content_type, permissions_policy, reporting_endpoints
from modules.cors import CrossOriginResourceSharing
from modules.leaks import LeaksFinder

class PtResHeaders:
    """Script connects to target <url> and analyses response headers"""

    OBSERVED_HEADERS_MODULES = {
        "Content-Type": content_type.ContentType,
        "X-Frame-Options": x_frame_options.XFrameOptions,
        "X-Content-Type-Options": x_content_type_options.XContentTypeOptions,
        "Permissions-Policy": permissions_policy.PermissionsPolicy,
        "Strict-Transport-Security": strict_transport_security.StrictTransportSecurity,
        "Referrer-Policy": referrer_policy.ReferrerPolicy,
        "Content-Security-Policy": content_security_policy.ContentSecurityPolicy,
        "Reporting-Endpoints": reporting_endpoints.ReportingEndpoints,
    }

    DEPRECATED_HEADERS = [
        "X-Frame-Options",
        "X-XSS-Protection"
    ]

    def __init__(self, args):
        self.ptjsonlib   = ptjsonlib.PtJsonLib()
        self.json        = args.json
        self.args        = args

    def run(self, args) -> None:
        """Main method"""

        ptprint(f"Connecting to URL: {args.url}", "TITLE", not args.json, colortext=True, end=" ")
        response, dump = self.load_url(args)
        headers: dict = response.headers

        found_missing_headers: list = []
        found_deprecated_headers: list = []

        ptprint(f"[{response.status_code}]", "TEXT", not args.json)
        ptprint(f"Response Headers:", "INFO", not args.json, colortext=True)

        # Print all response headers
        self.print_response_headers(headers)

        # Print info leaking headers
        LeaksFinder(args, self.ptjsonlib).find_technology_headers(headers)
        LeaksFinder(args, self.ptjsonlib).find_leaking_domains(headers)

        _cors_headers = [h.lower() for h in ["Cross-Origin-Resource-Policy", "Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy", "Access-Control-Max-Age", "Access-Control-Expose-Headers", "Access-Control-Allow-Credentials", "Access-Control-Allow-Headers", "Access-Control-Allow-Methods", "Access-Control-Allow-Origin"]]
        if any(key.startswith("cross-origin") or key in _cors_headers for key in (header.lower() for header in headers.keys())):
            CrossOriginResourceSharing().test(args=args, headers=headers)

        # Test observed headers for proper configuraton
        for observed_header, handler_function in self.OBSERVED_HEADERS_MODULES.items():
            if observed_header.lower() in (header.lower() for header in headers.keys()):
                # Pokud hlavička existuje, zavolejte příslušnou funkci
                handler_function(self.ptjsonlib, args, observed_header, headers[observed_header]).test_header(header_value=headers[observed_header])
                if observed_header.lower() in [h.lower() for h in self.DEPRECATED_HEADERS]:
                    found_deprecated_headers.append(observed_header)
            else:
                found_missing_headers.append(observed_header)

        ptprint(" ", condition=not args.json)
        if found_deprecated_headers:
            ptprint(f"Deprecated security headers:", bullet_type="WARNING", condition=not args.json)
            for header in found_deprecated_headers:
                ptprint(f"{header}", bullet_type="TEXT", condition=not args.json, indent=8)
                self.ptjsonlib.add_vulnerability(f"WARNIG-DEPRECATED-HEADER-{header}")
            ptprint(f" ", bullet_type="TEXT", condition=not args.json)

        if found_missing_headers:
            ptprint(f"Missing security headers:", bullet_type="ERROR", condition=not args.json)
            for header in found_missing_headers:
                ptprint(f"{header}", bullet_type="TEXT", condition=not args.json, indent=8)
                self.ptjsonlib.add_vulnerability(f"MISSING-HEADER-{header}")

        self.ptjsonlib.set_status("finished")
        ptprint(self.ptjsonlib.get_result_json(), "", self.json)

    def load_url(self, args):
        try:
            response, dump = ptmisclib.load_url(args.url, args.method, data=args.data, headers=args.headers, cache=args.cache, redirects=args.redirects, proxies=args.proxy, timeout=args.timeout, dump_response=True)
            return (response, dump)
        except Exception as e:
            ptprint(f"[err]", "TEXT", not args.json)
            self.ptjsonlib.end_error(f"Error retrieving response from server.", args.json)

    def print_response_headers(self, headers: dict):
        """Print all response headers"""
        for header_name, header_value in headers.items():
            ptprint(f"{header_name}: {header_value}", "ADDITIONS", not self.args.json, colortext=True, indent=4)

def get_help():
    return [
        {"description": ["Script connects to target <url> and analyses response headers"]},
        {"usage": ["ptresheaders <options>"]},
        {"usage_example": [
            "ptresheaders -u https://www.example.com",
            "ptresheaders -u https://www.example.com -p 127.0.0.1:8080",
        ]},
        {"options": [
            ["-u",  "--url",                    "<url>",            "Connect to URL"],
            ["-p",  "--proxy",                  "<proxy>",          "Set proxy"],
            ["-c",  "--cookie",                 "<cookie>",         "Set cookie"],
            ["-H",  "--headers",                "<header:value>",   "Set headers"],
            ["-d",  "--data",                   "<data>",           "Send request data"],
            ["-T",  "--timeout",                "",                 "Set timeout"],
            ["-m",  "--method",                 "",                 "Set method (default GET)"],
            ["-a",  "--user-agent",             "<agent>",          "Set User-Agent"],
            ["-r",  "--redirects",              "",                 "Follow redirects"],
            ["-C",  "--cache",                  "",                 "Enable HTTP cache"],
            ["-j",  "--json",                   "",                 "Enable JSON output"],
            ["-v",  "--version",                "",                 "Show script version and exit"],
            ["-h",  "--help",                   "",                 "Show this help message and exit"],
        ]
        }]


def parse_args():
    parser = argparse.ArgumentParser(add_help="False", description=f"{SCRIPTNAME} <options>")
    exclusive = parser.add_mutually_exclusive_group(required=True)
    exclusive.add_argument("-u",  "--url",            type=str)
    parser.add_argument("-m",  "--method",         type=str.upper, default="GET")
    parser.add_argument("-p",  "--proxy",          type=str)
    parser.add_argument("-d",  "--data",           type=str)
    parser.add_argument("-T",  "--timeout",        type=int, default=10)
    parser.add_argument("-a",  "--user-agent",     type=str, default="Penterep Tools")
    parser.add_argument("-c",  "--cookie",         type=str)
    parser.add_argument("-H",  "--headers",        type=ptmisclib.pairs, nargs="+")
    parser.add_argument("-r",  "--redirects",      action="store_true")
    parser.add_argument("-C",  "--cache",          action="store_true")
    parser.add_argument("-j",  "--json",           action="store_true")
    parser.add_argument("-v",  "--version",        action='version', version=f'{SCRIPTNAME} {__version__}')

    parser.add_argument("--socket-address",        type=str, default=None)
    parser.add_argument("--socket-port",           type=str, default=None)
    parser.add_argument("--process-ident",         type=str, default=None)


    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)

    args = parser.parse_args()
    args.headers = ptnethelper.get_request_headers(args)
    args.headers.update({"Referer": "https://www.example.com/", "Origin": "https://www.example.com/"})
    args.proxy = {"http": args.proxy, "https": args.proxy}

    ptprinthelper.print_banner(SCRIPTNAME, __version__, args.json)
    return args


def main():
    global SCRIPTNAME
    SCRIPTNAME = "ptresheaders"
    requests.packages.urllib3.disable_warnings()
    args = parse_args()
    script = PtResHeaders(args)
    script.run(args)


if __name__ == "__main__":
    main()
