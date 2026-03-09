# https://github.com/BioStatMatt/sas7bdat/blob/master/vignettes/sas7bdat.rst#sas7bdat-header
import sys
import struct

from dataclasses import dataclass
from typing import Optional
from constant import *
from datetime import datetime, timedelta


@dataclass
class SubheaderPointer:
    offset: int = None
    length: int = None
    compression: int = None
    type: int = None


@dataclass
class PageMetadata:
    byte_meta: bytes = None
    page_type: int | None = None
    page_block_count: int | None = None
    page_subheader_count: int | None = None
    page_cache: bytes | None = None


@dataclass
class HeaderMetadata:
    encoding: str = "utf-8"
    need_bytes: str | None = None
    date_created: str | None = None
    date_modified: str | None = None
    sas_version: str | None = None
    page_size: int | None = None
    header_length: int | None = None
    page_count: int | None = None
    platform: str | None = "unknown"
    name: str | None = None
    file_type: str | None = None
    page_bit_offset: int | None = None
    subheader_pointer_length: int | None = None
    compression: int | None = None
    row_count: int | None = None
    row_length: int | None = None
    col_count_p1: int = 0
    col_count_p2: int = 0
    mix_page_row_count: int | None = None
    lcs: int | None = None
    lcp: int | None = None
    column_count: int | None = None

    def __repr__(self):
        return f"""----------------------------------------------
        encoding: {self.encoding}
        need_byteswap: {self.need_bytes}
        date_created: {self.date_created}
        date_modified: {self.date_modified}
        sas_version: {self.sas_version}   
        page_count: {self.page_count}
        page_size: {self.page_size}   
        header_length: {self.header_length}
        platform: {self.platform}  
        file_type: {self.file_type}
        row_count: {self.row_count}   
        row_length: {self.row_length}
        col_count_p1: {self.col_count_p1}   
        col_count_p2: {self.col_count_p2}
        mix_page_row_count: {self.mix_page_row_count}  
        lcs: {self.lcs}
        lcp: {self.lcp}
        column_count: {self.column_count}
        compression: {self.compression}
        """


class SasHeader(object):
    def __init__(self, parent: "SasRead"):
        self.parent = parent
        self.page_metadata = PageMetadata()

        self.header_metadata = HeaderMetadata()

        self.align1: int = 0
        self.align2: int = 0

        self.u64: bool = False

        self.pointer = None

        self._init_setup()
        self._read_metadata()

    def _init_setup(self):
        if self._read_byte(align_1_offset, 1) == u64_byte_checker_value:
            self.align2 = align_2_value
            self.u64 = True

        if self._read_byte(align_2_offset, 1) == align_1_checker_value:
            self.align1 = align_1_value

        self.header_metadata.page_bit_offset = (
            page_bit_offset_x64 if self.u64 else page_bit_offset_x86
        )

        self.header_metadata.subheader_pointer_length = (
            subheader_pointer_length_x64 if self.u64 else subheader_pointer_length_x86
        )

        self.int_length = 8 if self.u64 else 4

    def _read_byte(
        self,
        offset: int,
        length: int = 0,
        align1: int = 0,
        align2: int = 0,
        fmt: str = None,
        byte_cache: bytes = None,
    ) -> bytes | float | int:
        if not byte_cache:
            res = self.parent.byte_file[offset + align1 : offset + length + align2]
        else:
            res = byte_cache[offset + align1 : offset + length + align2]

        _fmt = fmt

        if fmt == "i" and self.u64:
            _fmt = "q"
        elif fmt == "s":
            _fmt = "{}s".format(min(length, len(res)))

        if self.header_metadata.need_bytes == "little":
            _fmt = "<{}".format(_fmt)
        elif self.header_metadata.need_bytes == "big":
            _fmt = ">{}".format(_fmt)

        if fmt == "d":
            res = struct.unpack(str(_fmt), res)[0]
        elif fmt == "s":
            val = res.strip(b"\x00")
            res = struct.unpack(_fmt, val)[0].decode()
        elif fmt == "i":
            res = struct.unpack(_fmt, res)[0]
        elif fmt == "h":
            res = struct.unpack(_fmt, res)[0]
        return res

    def _read_metadata(self):
        # Определяем кодировку файла
        encode = ord(
            self.parent.byte_file[encoding_offset : encoding_offset + encoding_length]
        )
        if encode in encoding_names:
            self.header_metadata.encoding = encoding_names[encode]
        else:
            raise ValueError("Ошиибка в определении кодировки файла")

        buf = self._read_byte(endianness_offset, endianness_length)
        if buf == b"\x01":
            align = align_1_value
            self.header_metadata.need_bytes = sys.byteorder
        else:
            align = 0
            self.header_metadata.need_bytes = sys.byteorder

        # Дата создания таблицы
        val = self._read_byte(
            date_created_offset,
            date_created_length,
            align1=align,
            align2=align,
            fmt="d",
        )
        self.header_metadata.date_created = epoch + timedelta(seconds=val)

        # Дата обновления таблицы
        val = self._read_byte(
            date_modified_offset,
            date_modified_length,
            align1=align,
            align2=align,
            fmt="d",
        )
        self.header_metadata.date_modified = epoch + timedelta(seconds=val)

        # Определяю версию SAS
        val = self._read_byte(
            sas_version_offset + self.align1 + self.align2, sas_version_length, fmt="s"
        )
        self.header_metadata.sas_version = val

        # Определяем платформу
        val = self._read_byte(platform_offset, platform_length)
        if val == b"1":
            self.header_metadata.platform = "Windows"
        elif val == b"2":
            self.header_metadata.platform = "Linux"
        elif val == b"3":
            self.header_metadata.platform = "MacOS"

        # Определяем тип файла
        val = self._read_byte(file_type_offset, file_type_length, fmt="s")
        self.header_metadata.file_type = val

        # Определяем длинну страниц
        page_size = self._read_byte(
            page_size_offset + self.align1, page_size_length, fmt="i"
        )
        self.header_metadata.page_size = page_size

        # Определяем количество страниц
        page_count = self._read_byte(
            page_count_offset + self.align1, page_count_length, fmt="i"
        )
        self.header_metadata.page_count = page_count

        header_length = self._read_byte(
            header_size_offset + self.align1, header_size_length, fmt="i"
        )
        self.header_metadata.header_length = header_length

    def parse_header(self):
        self._read_metadata()
        # for page in range(1, self.header_metadata.page_count):
        for page in range(1, 5):
            self._read_page(page=page)

    def _read_page(self, page: int) -> None:
        self._read_page_header(page=page)
        if self.page_metadata.page_type in page_meta_mix_data:
            self._read_page_metadata()

    def _read_subheader_pointer(self, offset: int, index: int) -> SubheaderPointer:

        total_offset = offset + self.header_metadata.subheader_pointer_length * index

        subheader_offset = self._read_byte(
            total_offset,
            self.int_length,
            fmt="i",
            byte_cache=self.page_metadata.page_cache,
        )

        subheader_length = self._read_byte(
            total_offset + self.int_length,
            self.int_length,
            fmt="i",
            byte_cache=self.page_metadata.page_cache,
        )

        subheader_compression = self._read_byte(
            total_offset + self.int_length * 2,
            fmt="b",
            byte_cache=self.page_metadata.page_cache,
        )

        subheader_type = self._read_byte(
            total_offset + self.int_length * 2 + 1,
            fmt="b",
            byte_cache=self.page_metadata.page_cache,
        )

        return SubheaderPointer(
            subheader_offset, subheader_length, subheader_compression, subheader_type
        )

    def _get_subheader_class(self, signature, compression, type):
        index = subheader_signature_to_index.get(signature)
        if (
            self.header_metadata.compression is not None
            and index is None
            and (compression == compressed_subheader_id or compression == 0)
            and type == compressed_subheader_id
        ):
            index = SASIndex.data_subheader_index
        return index

    def _read_page_metadata(self) -> None:
        for i in range(self.page_metadata.page_subheader_count):
            self.pointer = self._read_subheader_pointer(
                subheader_pointers_offset + self.header_metadata.page_bit_offset,
                i,
            )
            if not self.pointer.length:
                continue

            if self.pointer.compression != truncated_subheader_id:
                subheader_signature = self._read_byte(
                    self.pointer.offset,
                    self.int_length,
                    byte_cache=self.page_metadata.page_cache,
                )

                subheader_index = self._get_subheader_class(
                    subheader_signature, self.pointer.compression, self.pointer.type
                )

                if subheader_index is not None:
                    if subheader_index != SASIndex.data_subheader_index:
                        match subheader_index:
                            case SASIndex.row_size_index:
                                self._row_size_subheader(self.pointer.offset)
                            case SASIndex.column_size_index:
                                self._column_size_subheader(self.pointer.offset)
                            case SASIndex.subheader_counts_index:
                                pass
                            case SASIndex.column_text_index:
                                self._column_text_subheader(self.pointer.offset)
                            case SASIndex.column_name_index:
                                self._column_name_subheader(
                                    self.pointer.offset, self.pointer.length
                                )

    def _read_page_header(self, page: int) -> None:

        self.page_metadata.page_cache = self._read_byte(
            self.header_metadata.page_size * page, self.header_metadata.page_size
        )

        self.page_metadata.page_type = self._read_byte(
            self.header_metadata.page_size * page
            + page_type_offset
            + self.header_metadata.page_bit_offset,
            page_type_length,
            fmt="h",
        )

        self.page_metadata.page_block_count = self._read_byte(
            self.header_metadata.page_size * page
            + block_count_offset
            + self.header_metadata.page_bit_offset,
            block_count_length,
            fmt="h",
        )

        self.page_metadata.page_subheader_count = self._read_byte(
            self.header_metadata.page_size * page
            + subheader_count_offset
            + self.header_metadata.page_bit_offset,
            subheader_count_length,
            fmt="h",
        )

    def _row_size_subheader(self, offset) -> None:
        lcs = offset + (682 if self.u64 else 354)
        lcp = offset + (706 if self.u64 else 378)

        self.header_metadata.row_length = self._read_byte(
            offset + row_length_offset_multiplier * self.int_length,
            self.int_length,
            fmt="i",
            byte_cache=self.page_metadata.page_cache,
        )

        self.header_metadata.row_count = self._read_byte(
            offset + row_count_offset_multiplier * self.int_length,
            self.int_length,
            fmt="i",
            byte_cache=self.page_metadata.page_cache,
        )

        self.header_metadata.col_count_p1 = self._read_byte(
            offset + col_count_p1_multiplier * self.int_length,
            self.int_length,
            fmt="i",
            byte_cache=self.page_metadata.page_cache,
        )

        self.header_metadata.col_count_p2 = self._read_byte(
            offset + col_count_p2_multiplier * self.int_length,
            self.int_length,
            fmt="i",
            byte_cache=self.page_metadata.page_cache,
        )

        self.header_metadata.mix_page_row_count = self._read_byte(
            offset + row_count_on_mix_page_offset_multiplier * self.int_length,
            self.int_length,
            fmt="i",
            byte_cache=self.page_metadata.page_cache,
        )
        self.header_metadata.lcs = self._read_byte(
            lcs, 2, fmt="h", byte_cache=self.page_metadata.page_cache
        )
        self.header_metadata.lcp = self._read_byte(
            lcp, 2, fmt="h", byte_cache=self.page_metadata.page_cache
        )

    def _column_size_subheader(self, offset) -> None:
        self.header_metadata.column_count = self._read_byte(
            offset + self.int_length,
            self.int_length,
            fmt="i",
            byte_cache=self.page_metadata.page_cache,
        )

        if (
            self.header_metadata.col_count_p1 + self.header_metadata.col_count_p2
            != self.header_metadata.column_count
        ):
            print("Error: col_count_p1 + col_count_p2 != column_count")

    def _column_text_subheader(self, offset) -> None:
        text_block_size = self._read_byte(
            offset + self.int_length,
            text_block_size_length,
            fmt="h",
            byte_cache=self.page_metadata.page_cache,
        )

        vals = self._read_byte(
            offset + self.int_length,
            text_block_size,
            byte_cache=self.page_metadata.page_cache,
        )

        self.parent.column_names_strings.append(vals)

        if len(self.parent.column_names_strings) > 0:
            for cl in compression_literals:
                if cl in self.parent.column_names_strings:
                    self.header_metadata.compression = cl
                    break

    def _column_name_subheader(self, offset, length) -> None:

        for i in range(self.header_metadata.col_count_p1):
            text_subheader = (
                offset + self.int_length
                + column_name_pointer_length * (i + 1)
                + column_name_text_subheader_offset
            )
            col_name_offset = (
                offset + self.int_length
                + column_name_pointer_length * (i + 1)
                + column_name_offset_offset
            )
            col_name_length = (
                offset + self.int_length
                + column_name_pointer_length * (i + 1)
                + column_name_length_offset
            )

            idx = self._read_byte(
                text_subheader,
                column_name_text_subheader_length,
                fmt="h",
                byte_cache=self.page_metadata.page_cache,
            )
            col_offset = self._read_byte(
                col_name_offset,
                column_name_offset_length, fmt="h",
                byte_cache=self.page_metadata.page_cache,
            )
            col_len = self._read_byte(
                col_name_length,
                column_name_length_length, fmt="h",
                byte_cache=self.page_metadata.page_cache,
            )
            name = self.parent.column_names_strings[idx]
            self.parent.column_names.append(name[col_offset: col_offset + col_len])


class SasRead:
    def __init__(self, path_file: str):
        self.byte_order = None
        self.need_byteswap = None
        self.page_bit_offset = None

        self.align1: int = 0
        self.align2: int = 0

        self.column_names_strings = []
        self.column_names = []

        self.byte_file = self._open_file(path_file=path_file)

        self.sas_header = SasHeader(self)
        self.header_metadata = self.sas_header.header_metadata
        self.sas_header.parse_header()

    @staticmethod
    def _open_file(path_file: str) -> bytes:
        with open(path_file, "rb") as f:
            return f.read()

    def readline(self):
        bit_offset = self.header_metadata.page_bit_offset
        subheader_pointer_length = self.header_metadata.subheader_pointer_length

        return self.byte_file

    def header(self):
        print(self.column_names)
        return self.header_metadata


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
