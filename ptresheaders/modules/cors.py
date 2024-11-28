#from modules.headers._header_test_base import HeaderTestBase
from ptlibs.ptprinthelper import ptprint

class CrossOriginResourceSharing:

    def test(self, args, headers: dict):
        _cors_headers = [h.lower() for h in [
            "Cross-Origin-Resource-Policy", "Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy",
            "Access-Control-Max-Age", "Access-Control-Expose-Headers", "Access-Control-Allow-Credentials",
            "Access-Control-Allow-Headers", "Access-Control-Allow-Methods", "Access-Control-Allow-Origin"
        ]]

        cross_origin_headers = [
            {key: value} for key, value in headers.items()
            if key.lower().startswith("cross-origin") or key.lower() in _cors_headers
        ]

        if cross_origin_headers:
            ptprint("CORS Header:", bullet_type="TITLE", condition=not args.json, colortext=True, newline_above=True)
            for header_dict in cross_origin_headers:
                _key = list(header_dict.keys())[0]
                _value = header_dict[_key]
                output_value = _value
                bullet = ""

                if "access-control-allow-origin" == _key.lower():
                    for v in _value.split(" "):
                        if v == "*":
                            bullet = "VULN"
                            break
                        elif v == "https://www.example.com/":
                            bullet = "VULN"
                            output_value += " (reflective origin)"
                            break

                ptprint(f'{_key}: {output_value}', bullet_type=bullet, condition=not args.json, indent=4)