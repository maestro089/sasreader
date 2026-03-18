from dataclasses import dataclass

from constant import *

import struct


@dataclass
class SASProperties:
    align1 = 0
    align2 = 0
    u64 = False
    need_bytes = "little"

    def __str__(self):
        return f"align1: {self.align1}, align2: {self.align2}, u64: {self.u64}"


class ConvertByte:
    def __init__(self, properties: SASProperties):
        self._properties = properties

    def _read(
        self,
        offset: int,
        length: int = 0,
        align1: int = 0,
        align2: int = 0,
        fmt: str = None,
        cache: bytes = None,
    ) -> bytes | float | int:

        res_cache = cache[offset + align1: offset + length + align2]

        _fmt = fmt

        if fmt == "i" and self._properties.u64:
            _fmt = "q"
        elif fmt == "s":
            _fmt = "{}s".format(min(length, len(res_cache)))

        if self._properties.need_bytes == "little":
            _fmt = "<{}".format(_fmt)
        elif self._properties.need_bytes == "big":
            _fmt = ">{}".format(_fmt)

        if fmt == "d":
            result = struct.unpack(str(_fmt), res_cache)[0]
        elif fmt == "s":
            val = res_cache.strip(b"\x00")
            result = struct.unpack(_fmt, val)[0].decode()
        elif fmt == "i":
            result = struct.unpack(_fmt, res_cache)[0]
        elif fmt == "h":
            result = struct.unpack(_fmt, res_cache)[0]
        elif fmt == "b":
            result = struct.unpack(_fmt, res_cache)[0]
        else:
            result = res_cache
        return result


class SasHeader:
    def __init__(self, byte_file):
        self._byte_file = byte_file
        self.properties = SASProperties()

        self._check_magic(self._byte_file[0:288])
        self._check_u64(self._byte_file[0:64])

        self._read_byte = ConvertByte(properties=self.properties)

    @staticmethod
    def _check_magic(cache: bytes = None):
        if cache[0: len(magic_number)] == magic_number:
            ...
        else:
            print(cache[0: len(magic_number)])
            raise Exception("magic number is not ok")

    def _check_u64(self, cache: bytes = None):
        if cache[align_1_offset: align_1_offset + 1] == u64_byte_checker_value:
            self.properties.align2 = align_2_value
            self.properties.u64 = True
        if cache[align_2_offset: align_2_offset + 1] == align_1_checker_value:
            self.properties.align1 = align_1_value


class SasReader:
    def __init__(self, path: str):
        self.path = path

        self._byte_file = self._read_sas7bdat(path=self.path)
        self.header = SasHeader(byte_file=self._byte_file)

    @staticmethod
    def _read_sas7bdat(path: str):
        with open(path, "rb") as f:
            result = f.read()
        return result

    def test(self):
        return self.header.properties


res = SasReader(path="test.sas7bdat").test()

print(res)


# Header:
# 	col_count_p1: 813
# 	col_count_p2: 0
# 	column_count: 813
# 	compression: SASYZCRL
# 	creator: None
# 	creator_proc: DATASTEP
# 	date_created: 2025-11-10 22:00:27.372000
# 	date_modified: 2025-11-10 22:00:27.372000
# 	endianess: little
# 	file_type: DATA
# 	filename: gss2024.sas7bdat
# 	header_length: 65536
# 	lcp: 8
# 	lcs: 0
# 	mix_page_row_count: 3
# 	name:
# 	os_name:
# 	os_type:
# 	page_count: 140
# 	page_length: 65536
# 	platform: windows
# 	row_count: 3309
# 	row_length: 3308
# 	sas_release: 9.0401M7
# 	server_type: X64_SRV19
# 	u64: False
