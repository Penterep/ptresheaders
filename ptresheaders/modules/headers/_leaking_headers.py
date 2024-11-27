from ptlibs.ptprinthelper import ptprint, out_if

INTERESTING_HEADERS = [
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


def find_interesting_headers(headers: dict):
    """Finds interesting headers"""
    output = ""
    for header_name, header_value in headers.items():
        if header_name.lower() in INTERESTING_HEADERS:
            output += out_if(string=f"{header_name}: {header_value}\n", bullet_type="ADDITIONS", colortext=True, indent=4)
    if output:
        output = output.rstrip("\n")
        ptprint(f"Interesting headers:", "INFO", True, newline_above=True, colortext=True)
        ptprint(output, "TEXT", True, indent=0, end="")