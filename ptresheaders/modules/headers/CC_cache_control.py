from modules.headers._header_test_base import HeaderTestBase
from ptlibs.ptprinthelper import ptprint

import re

class CacheControl(HeaderTestBase):
    def test_header(self, header_value: str):
        header_values_list: list = header_value.split(", ")