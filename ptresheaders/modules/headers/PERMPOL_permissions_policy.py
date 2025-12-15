import re
from modules.headers._header_test_base import HeaderTestBase
from ptlibs.ptprinthelper import ptprint

class PermissionsPolicy(HeaderTestBase):

    standardized_permissions: list = [
        "accelerometer",
        "ambient-light-sensor",
        "autoplay",
        "battery",
        "camera",
        "cross-origin-isolated",
        "display-capture",
        "document-domain",
        "encrypted-media",
        "execution-while-not-rendered",
        "execution-while-out-of-viewport",
        "fullscreen",
        "geolocation",
        "gyroscope",
        "keyboard-map",
        "magnetometer",
        "microphone",
        "midi",
        "navigation-override",
        "payment",
        "picture-in-picture",
        "publickey-credentials-get",
        "screen-wake-lock",
        "sync-xhr",
        "usb",
        "web-share",
        "xr-spatial-tracking",
        "clipboard-read",
        "clipboard-write",
        "gamepad",
        "speaker-selection",
        "conversion-measurement",
        "focus-without-user-activation",
        "hid",
        "idle-detection",
        "interest-cohort",
        "serial",
        "sync-script",
        "trust-token-redemption",
        "unload",
        "window-placement",
        "vertical-scroll"
    ]

    PERMISSIONS_POLICY_RE = re.compile(r"([a-zA-Z-]+)\s*=\s*\([^)]*\)") # Matches directives like "geolocation=(self 'none')"

    def test_header(self, header_value: str) -> None:
        """
        Tests the provided header value for compliance with the Content Security Policy.

        :param header_value: The CSP header value to be tested.
        :type header_value: str
        """
        #missing_permissions: list = [p for p in self.standardized_permissions if p not in [j.split("=")[0] for j in response_permissions_list]]
        response_permissions: list = self._parse_permissions(header_value)

        if not response_permissions:
            ptprint("Permissions-Policy header has invalid syntax", bullet_type="VULN", condition=not self.args.json, indent=4)
            self.ptjsonlib.add_vulnerability("PTV-WEB-HTTP-PERMPOLINV")
            return

        missing_permissions: list = [p for p in self.standardized_permissions if p not in response_permissions]

        self._print_permissions("Values", sorted(response_permissions), "OK")
        
        ptprint(" ", "", condition=not self.args.json and bool(response_permissions), indent=0)
        self._print_permissions("Missing directives", sorted(missing_permissions), "WARNING")

    def _print_permissions(self, label:str, permissions: list, bullet="OK") -> None:
        """
        Prints the permissions with appropriate formatting.
        """
        if not permissions:
            return
        
        ptprint(f"{label}:", "", condition=not self.args.json, indent=4)
        
        for p in permissions:
            if "*" in p:
                self.ptjsonlib.add_vulnerability("PTV-WEB-HTTP-PERMPOLINV")
            ptprint(p, bullet_type="VULN" if "*" in p else bullet, condition=not self.args.json, indent=8)

    def _parse_permissions(self, header_value: str) -> list:
        """
        Extracts directive names from a Permissions-Policy header.
        """
        return self.PERMISSIONS_POLICY_RE.findall(header_value)