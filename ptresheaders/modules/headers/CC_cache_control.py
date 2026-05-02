from modules.headers._header_test_base import HeaderTestBase
from ptlibs.ptprinthelper import ptprint

import re

class CacheControl(HeaderTestBase):
    def test_header(self, header_value: str):
        raw_directives = [v.strip() for v in header_value.split(",")]
        lower_directives = [v.lower() for v in raw_directives]

        content_type = self.response.headers.get("Content-Type", "").lower()
        is_sensitive = any(ct in content_type for ct in ["text/html", "json", "xml"])
        has_max_age_zero = any(self._is_max_age_zero(directive) for directive in lower_directives)

        required_directives  = ["no-cache", "no-store", "must-revalidate"]
        dangerous_directives = ["public", "immutable"]

        has_vuln = False

        for raw_dir, low_dir in zip(raw_directives, lower_directives):
            is_dangerous = False

            if low_dir in dangerous_directives:
                is_dangerous = True
            else:
                match = re.match(r'^(?:s-maxage|max-age)\s*=\s*(\d+)$', low_dir)
                if match and int(match.group(1)) > 0:
                    is_dangerous = True

            if is_sensitive and is_dangerous:
                ptprint(raw_dir, bullet_type="VULN", condition=not self.args.json, indent=8)
                has_vuln = True
            else:
                ptprint(raw_dir, bullet_type="OK", condition=not self.args.json, indent=8)

        if is_sensitive:
            for req in required_directives:
                if req not in lower_directives:
                    if req == "must-revalidate" and has_max_age_zero:
                        ptprint(
                            f"{req} not set; max-age=0 present",
                            bullet_type="WARNING",
                            condition=not self.args.json,
                            indent=8
                        )
                    else:
                        ptprint(f"Missing: {req}", bullet_type="VULN", condition=not self.args.json, indent=8)
                        has_vuln = True

            if has_vuln:
                self.ptjsonlib.add_vulnerability("PTV-WEB-CACHE-CLSENS", header_contents=header_value)

    def _is_max_age_zero(self, directive: str) -> bool:
        return bool(re.match(r'^max-age\s*=\s*0$', directive))
