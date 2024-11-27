from ptlibs.ptprinthelper import ptprint, out_if

LEAKING_HEADERS = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "accept-language",
    "x-real-ip",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-cluster-client-ip",
    "x-content-digest",
    "x-request-id",
    "x-ua-compatible",
    "x-b3-traceid",
    "x-b3-spanid",
    "x-b3-parentspanid",
    "x-tyk-authorization",
    "x-amz-id-2",
    "x-amz-request-id",
    "via",
    "etag",
    "x-cloud-trace-context",
    "x-microsoft-diagnostics-applicationanalytics",
    "x-microsoft-diagnostics-serviceversion",
    "x-microsoft-request-id"
    "cache-control",
]

class LeaksFinder():
    def __init__(self, args, ptjsonlib):
        self.ptjsonlib = ptjsonlib
        self.args = args

    def find_technology_headers(self, headers: dict):
        leaking_headers = [
            out_if(string=f"{header_name}: {header_value}\n", bullet_type="TEXT", indent=4)
            for header_name, header_value in headers.items()
            if header_name.lower() in LEAKING_HEADERS
        ]

        output = "".join(leaking_headers).rstrip("\n")
        ptprint(f"Info leaking headers:", "INFO", not self.args.json and output, newline_above=True, colortext=True)
        ptprint(output, "TEXT", True, indent=0, end="\n")

    def find_leaking_domains(self, headers: dict):
        pass