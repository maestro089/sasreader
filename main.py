from dataclasses import dataclass
from datetime import timedelta

from constant import *

import struct


@dataclass
class SASProperties:
    align1 = 0
    align2 = 0
    u64 = False
    endianness = None
    platform = None
    encode = "utf-8"
    date_created = None
    date_modified = None
    page_size = None
    page_count = None
    sas_version = None
    header_size = None
    page_bit_offset = page_bit_offset_x86

    def __str__(self):
        return f"""
                align1: {self.align1}
                align2: {self.align2}
                u64: {self.u64}
                endianness: {self.endianness}
                platform: {self.platform}
                encode: {self.encode}
                date_created: {self.date_created}
                date_modified: {self.date_modified}
                page_size(PL): {self.page_size}
                page_count: {self.page_count}
                sas_version: {self.sas_version}
                header_size(HL): {self.header_size}
                page_bit_offset: {self.page_bit_offset}
               """


class ConvertByte:
    def __init__(self, properties: SASProperties):
        self._properties = properties

    def read(
        self,
        offset: int,
        length: int = 0,
        align1: int = 0,
        align2: int = 0,
        fmt: str = None,
        cache: bytes = None,
    ) -> bytes | float | int:

        res_cache = cache[offset + align1 : offset + length + align2]

        _fmt = fmt

        if fmt == "i" and self._properties.u64:
            _fmt = "q"
        elif fmt == "s":
            _fmt = "{}s".format(min(length, len(res_cache)))

        if self._properties.endianness == "little":
            _fmt = "<{}".format(_fmt)
        elif self._properties.endianness == "big":
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


class SasReadHeaderFile:
    def __init__(self, byte_file, properties: SASProperties):
        self._byte_file = byte_file
        self.properties = properties
        self._read_byte = ConvertByte(properties=self.properties)

        self._check_magic(self._byte_file[0:288])
        self._check_u64(self._byte_file[0:64])
        self._parse_metadata(self._byte_file)

    @staticmethod
    def _check_magic(cache: bytes = None):
        if cache[0 : len(magic_number)] != magic_number:
            print(cache[0 : len(magic_number)])
            raise Exception("magic number is not ok")

    def _check_u64(self, cache: bytes = None):
        if (
            self._read_byte.read(align_1_offset, 1, cache=cache)
            == u64_byte_checker_value
        ):
            self.properties.align2 = align_2_value
            self.properties.u64 = True
            self.properties.page_bit_offset = page_bit_offset_x64
        if (
            self._read_byte.read(align_2_offset, 1, cache=cache)
            == align_1_checker_value
        ):
            self.properties.align1 = align_1_value

    def _parse_metadata(self, cache: bytes = None):
        val = self._read_byte.read(endianness_offset, endianness_length, cache=cache)
        self.properties.endianness = "little" if val == b"\x01" else "big"

        val = self._read_byte.read(platform_offset, platform_length, cache=cache)
        self.properties.platform = "WIN" if val == b"2" else "UNIX"

        val = self._read_byte.read(
            encoding_offset, encoding_length, cache=cache, fmt="b"
        )
        self.properties.encode = encoding_names[val]

        val = self._read_byte.read(
            date_created_offset + self.properties.align1,
            date_created_length,
            cache=cache,
            fmt="d",
        )
        self.properties.date_created = epoch + timedelta(seconds=val)

        val = self._read_byte.read(
            date_modified_offset + self.properties.align1,
            date_modified_length,
            cache=cache,
            fmt="d",
        )
        self.properties.date_modified = epoch + timedelta(seconds=val)

        val = self._read_byte.read(
            page_size_offset + self.properties.align1,
            page_size_length,
            cache=cache,
            fmt="i",
        )
        self.properties.page_size = val

        val = self._read_byte.read(
            page_count_offset + self.properties.align1,
            page_count_length,
            cache=cache,
            fmt="i",
        )
        self.properties.page_count = val

        val = self._read_byte.read(
            sas_version_offset + self.properties.align1 + self.properties.align2,
            sas_version_length,
            cache=cache,
        )
        self.properties.sas_version = val

        val = self._read_byte.read(
            header_size_offset + self.properties.align1,
            header_size_length,
            cache=cache,
            fmt="i",
        )
        self.properties.header_size = val


@dataclass
class PointerPage:
    offset: int = None
    length: int = None
    compression: str = None
    type: str = None


@dataclass
class MetaPage:
    page_type = None
    page_block_count = None
    page_subheaders_count = None
    point: PointerPage = None


class SasReadMetaPage:
    def __init__(self, byte_file, properties: SASProperties):
        self._byte_file = byte_file
        self.properties = properties
        self._length = None
        self._subheader_pointer_length = None
        self._page_bit_offset = self.properties.page_bit_offset
        self._check_u64()
        self._read_byte = ConvertByte(properties=self.properties)

        self._metadata_pages = []
        self._meta_page = MetaPage()
        self._meta_page_pointer = PointerPage()
        self._cache = None
        self._parse_metadata()

    def _check_u64(self):
        self._length = 8 if self.properties.u64 else 4
        self._subheader_pointer_length = (
            subheader_pointer_length_x64
            if self.properties.u64
            else subheader_pointer_length_x86
        )

    def _read_meta_page(self):
        self._meta_page.page_type = self._read_byte.read(
            page_type_offset + self._page_bit_offset,
            page_type_length,
            cache=self._cache,
            fmt="h",
        )
        self._meta_page.page_block_count = self._read_byte.read(
            block_count_offset + self._page_bit_offset,
            block_count_length,
            cache=self._cache,
            fmt="h",
        )
        self._meta_page.page_subheaders_count = self._read_byte.read(
            subheader_count_offset + self._page_bit_offset,
            subheader_count_length,
            cache=self._cache,
            fmt="h",
        )

    def _get_pointer_page(self, index: int = None):
        total_offset = (
            subheader_pointers_offset
            + self._page_bit_offset
            + (self._subheader_pointer_length * index)
        )

        self._meta_page_pointer.offset = self._read_byte.read(
            total_offset, self._length, cache=self._cache, fmt="i"
        )

        self._meta_page_pointer.length = self._read_byte.read(
            total_offset + self._length, self._length, cache=self._cache, fmt="i"
        )

        self._meta_page_pointer.compression = self._read_byte.read(
            total_offset + self._length * 2, 1, cache=self._cache, fmt="b"
        )

        self._meta_page_pointer.type = self._read_byte.read(
            total_offset + self._length * 2 + 1, 1, cache=self._cache, fmt="b"
        )

        self._meta_page.point = self._meta_page_pointer
        print(self._meta_page)

    def _process_meta_page(self):
        for i in range(self._meta_page.page_subheaders_count):
            pointer = self._get_pointer_page(index=i)

    def _start_meta_page(self):
        self._read_meta_page()
        if self._meta_page.page_type in page_meta_mix_amd:
            self._process_meta_page()

    def _parse_metadata(self):
        for i in range(self.properties.page_count):
            self._cache = self._read_byte.read(
                self.properties.page_size * i,
                self.properties.page_size,
                cache=self._byte_file,
            )
            self._start_meta_page()


class SasReader:
    def __init__(self, path: str):
        self.path = path
        self.metadata_file = SASProperties()

        self._byte_file = self._read_sas7bdat(path=self.path)
        self.header = SasReadHeaderFile(
            byte_file=self._byte_file, properties=self.metadata_file
        )
        SasReadMetaPage(byte_file=self._byte_file, properties=self.metadata_file)

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
