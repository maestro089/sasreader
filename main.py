#https://github.com/BioStatMatt/sas7bdat/blob/master/vignettes/sas7bdat.rst#sas7bdat-header
import sys
import struct

from dataclasses import dataclass
from typing import Optional
from constant import *
from datetime import datetime, timedelta


@dataclass
class HeaderMetadata:
    encoding: str = "utf-8"
    need_byteswap: str | None = None
    date_created: str | None = None
    date_modified: str | None = None
    sas_version: str | None = None
    page_size: int | None = None
    page_count: int | None = None

    def __repr__(self):
        return f"""----------------------------------------------
        encoding: {self.encoding}
        need_byteswap: {self.need_byteswap}
        date_created: {self.date_created}
        date_modified: {self.date_modified}
        sas_version: {self.sas_version}   
        page_size: {self.page_size}     
        """


class SasHeader(object):
    def __init__(self, parent):
        self.parent = parent

        self.header_metadata = HeaderMetadata()

        self.s = "{}s"
        self.d = ""

        self.align1: int = 0
        self.align2: int = 0

        self.u64: bool = False

        self._init_setup()
        self._read_metadata()

    def _init_setup(self):
        if self.parent._read_byte(align_1_offset, 1) == u64_byte_checker_value:
            print("u64")
            self.align2 = align_2_value
            self.u64 = True

        if self.parent._read_byte(align_2_offset, 1) == align_1_checker_value:
            self.align1 = align_1_value

        self.page_bit_offset = page_bit_offset_x64 if self.u64 else page_bit_offset_x86

        self.subheader_pointer_length = subheader_pointer_length_x64 if self.u64 else subheader_pointer_length_x86

        self.int_length = 8 if self.u64 else 4

    def _read_metadata(self):
        # Определяем кодировку файла
        encode = ord(
            self.parent.byte_file[encoding_offset : encoding_offset + encoding_length]
        )
        if encode in encoding_names:
            self.header_metadata.encoding = encoding_names[encode]
        else:
            raise ValueError("Ошиибка в определении кодировки файла")

        buf = self.parent._read_byte(endianness_offset, endianness_length)
        if buf == b"\x01":
            self.d = "<%s" % "d"
            align = align_1_value
            self.header_metadata.need_byteswap = sys.byteorder
        else:
            self.d = ">%s" % "d"
            align = 0
            self.header_metadata.need_byteswap = sys.byteorder

        # Дата создания таблицы
        val = self.parent._read_byte(
            date_created_offset, date_created_length, align1=align, align2=align
        )
        val = struct.unpack(str(self.d), val)[0]
        self.header_metadata.date_created = epoch + timedelta(seconds=val)

        # Дата обновления таблицы
        val = self.parent._read_byte(
            date_modified_offset, date_modified_length, align1=align, align2=align
        )
        val = struct.unpack(str(self.d), val)[0]
        self.header_metadata.date_modified = epoch + timedelta(seconds=val)

        # Определяю версию SAS
        val = self.parent._read_byte(
            sas_version_offset + self.align1 + self.align2, sas_version_length
        ).strip(b"\x00")
        self.header_metadata.sas_version = struct.unpack(self.s.format(8), val)[
            0
        ].decode()

        # Определяем длинну страниц
        page_size = self.parent._read_byte(page_size_offset + self.align1, page_size_length)
        self.header_metadata.page_size = struct.unpack("i", page_size)[0]

        # Определяем количество страниц
        page_count = self.parent._read_byte(page_count_offset + self.align1, page_count_length)
        self.header_metadata.page_count = struct.unpack("i", page_count)[0]

        row_count = self.parent._read_byte(460 + row_length_offset_multiplier + self.int_length, self.int_length)

        # self.parent._process_subheader_pointers(subheader_pointers_offset + self.page_bit_offset, 0)

    def read_lines(self):
        pass

    def header(self):
        return "123"


class SasRead:
    def __init__(self, path_file: str):
        self.byte_order = None
        self.need_byteswap = None
        self.page_bit_offset = None

        self.align1: int = 0
        self.align2: int = 0

        self.u64: bool = False

        self.byte_file = self._open_file(path_file=path_file)

        self.sas_header = SasHeader(self)
        self.header_metadata = self.sas_header.header_metadata


    @staticmethod
    def _open_file(path_file: str) -> bytes:
        with open(path_file, "rb") as f:
            return f.read()

    def _read_byte(
        self, offset: int, length: int = 0, align1: int = 0, align2: int = 0
    ) -> bytes:
        res = self.byte_file[offset + align1: offset + length + align2]
        return res

    def header(self):
        return self.header_metadata

    # def _process_subheader_pointers(self, offset, subheader_pointer_index):
    #     subheader_pointer_length = self.subheader_pointer_length
    #     total_offset = (
    #         offset + subheader_pointer_length * subheader_pointer_index
    #     )
    #
    #     res = self._read_byte(total_offset, self.int_length)
    #
    #     print(res)
    #     print(struct.unpack("i", res)[0])


s = SasRead(path_file="gss2024.sas7bdat")

print(s.header())

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