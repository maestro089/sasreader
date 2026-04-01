from dataclasses import dataclass
from datetime import timedelta

from constant import *

import struct


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
    compression = None
    row_length = None
    row_count = None
    col_count_p1 = None
    col_count_p2 = None
    mix_page_row_count = None
    lcp = None
    lcs = None
    column_count = None

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
                compression: {self.compression}
                row_length: {self.row_length}
                row_count: {self.row_count}
                col_count_p1: {self.col_count_p1}
                col_count_p2: {self.col_count_p2}
                mix_page_row_count: {self.mix_page_row_count}
                lcp: {self.lcp}
                lcs: {self.lcs}
                column_count: {self.column_count}
               """


@dataclass
class Column:
    col_id: int = None
    name: str = None
    label: str = None
    format: str = None
    length: int = None
    type: int = None


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


class SasReadMetaPage:
    def __init__(self, byte_file, properties: SASProperties):
        self._byte_file = byte_file
        self.properties = properties
        self.column_names_strings = []
        self.column_names = []
        self.column_data_offsets = []
        self.column_data_lengths = []
        self.column_types = []
        self.pointer_page = []
        self.columns = []
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

    def get_subheader_pointer_length(self):
        return self._subheader_pointer_length

    def get_page_bit_offset(self):
        return self._page_bit_offset

    def get_metadata_pages(self):
        return self._metadata_pages

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
        print(self._meta_page.page_subheaders_count)

        self._metadata_pages.append(self._meta_page)

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

        return self._meta_page_pointer

    def _get_subheader_class(self, signature, compression, type):
        index = subheader_signature_to_index.get(signature)
        if (
            self.properties.compression is not None
            and index is None
            and (compression == compressed_subheader_id or compression == 0)
            and type == compressed_subheader_type
        ):
            index = SASIndex.data_subheader_index
        return index

    def _row_size_subheader(self, offset) -> None:
        lcs = offset + (682 if self.properties.u64 else 354)
        lcp = offset + (706 if self.properties.u64 else 378)

        self.properties.row_length = self._read_byte.read(
            offset + row_length_offset_multiplier * self._length,
            self._length,
            fmt="i",
            cache=self._cache,
        )

        self.properties.row_count = self._read_byte.read(
            offset + row_count_offset_multiplier * self._length,
            self._length,
            fmt="i",
            cache=self._cache,
        )

        self.properties.col_count_p1 = self._read_byte.read(
            offset + col_count_p1_multiplier * self._length,
            self._length,
            fmt="i",
            cache=self._cache,
        )

        self.properties.col_count_p2 = self._read_byte.read(
            offset + col_count_p2_multiplier * self._length,
            self._length,
            fmt="i",
            cache=self._cache,
        )

        self.properties.mix_page_row_count = self._read_byte.read(
            offset + row_count_on_mix_page_offset_multiplier * self._length,
            self._length,
            fmt="i",
            cache=self._cache,
        )
        self.properties.lcs = self._read_byte.read(lcs, 2, fmt="h", cache=self._cache)
        self.properties.lcp = self._read_byte.read(lcp, 2, fmt="h", cache=self._cache)

    def _column_size_subheader(self, offset) -> None:
        self.properties.column_count = self._read_byte.read(
            offset + self._length,
            self._length,
            fmt="i",
            cache=self._cache,
        )

        if (
            self.properties.col_count_p1 + self.properties.col_count_p2
            != self.properties.column_count
        ):
            print("Error: col_count_p1 + col_count_p2 != column_count")

    def _column_text_subheader(self, offset) -> None:
        text_block_size = self._read_byte.read(
            offset + self._length,
            text_block_size_length,
            fmt="h",
            cache=self._cache,
        )

        vals = self._read_byte.read(
            offset + self._length,
            text_block_size,
            cache=self._cache,
        )

        if len(vals) > 0:
            for cl in compression_literals:
                if cl in vals:
                    self.properties.compression = cl
                    break
        self.column_names_strings.append(vals)

    def _column_name_subheader(self, offset) -> None:

        for i in range(self.properties.col_count_p1):
            text_subheader = (
                offset
                + self._length
                + column_name_pointer_length * (i + 1)
                + column_name_text_subheader_offset
            )
            col_name_offset = (
                offset
                + self._length
                + column_name_pointer_length * (i + 1)
                + column_name_offset_offset
            )
            col_name_length = (
                offset
                + self._length
                + column_name_pointer_length * (i + 1)
                + column_name_length_offset
            )

            idx = self._read_byte.read(
                text_subheader,
                column_name_text_subheader_length,
                fmt="h",
                cache=self._cache,
            )
            col_offset = self._read_byte.read(
                col_name_offset,
                column_name_offset_length,
                fmt="h",
                cache=self._cache,
            )
            col_len = self._read_byte.read(
                col_name_length,
                column_name_length_length,
                fmt="h",
                cache=self._cache,
            )
            name = self.column_names_strings[idx]
            self.column_names.append(name[col_offset : col_offset + col_len])

    def _column_attributes_subheader(self, offset, length) -> None:
        column_attributes_vectors_count = (length - 2 * self._length - 12) // (
            self._length + 8
        )

        for i in range(column_attributes_vectors_count):
            col_data_offset = (
                offset
                + self._length
                + column_data_offset_offset
                + i * (self._length + 8)
            )
            col_data_len = (
                offset
                + 2 * self._length
                + column_data_length_offset
                + i * (self._length + 8)
            )
            col_types = (
                offset + 2 * self._length + column_type_offset + i * (self._length + 8)
            )

            self.column_data_offsets.append(
                self._read_byte.read(
                    col_data_offset,
                    self._length,
                    fmt="i",
                    cache=self._cache,
                )
            )

            self.column_data_lengths.append(
                self._read_byte.read(
                    col_data_len,
                    column_data_length_length,
                    fmt="i",
                    cache=self._cache,
                )
            )

            ctype = self._read_byte.read(
                col_types,
                column_type_length,
                fmt="b",
                cache=self._cache,
            )
            self.column_types.append("number" if ctype == 1 else "string")

    def _format_and_label_subheader(self, offset) -> None:

        text_subheader_format = self._read_byte.read(
            offset + column_format_text_subheader_index_offset + 3 * self._length,
            column_format_text_subheader_index_length,
            fmt="h",
            cache=self._cache,
        )

        format_idx = min(text_subheader_format, len(self.column_names_strings) - 1)

        format_start = self._read_byte.read(
            offset + column_format_offset_offset + 3 * self._length,
            column_format_offset_length,
            fmt="h",
            cache=self._cache,
        )

        format_len = self._read_byte.read(
            offset + column_format_length_offset + 3 * self._length,
            column_format_length_length,
            fmt="h",
            cache=self._cache,
        )

        text_subheader_label = self._read_byte.read(
            offset + column_label_text_subheader_index_offset + 3 * self._length,
            column_label_text_subheader_index_length,
            fmt="h",
            cache=self._cache,
        )

        label_idx = min(text_subheader_label, len(self.column_names_strings) - 1)

        label_start = self._read_byte.read(
            offset + column_label_offset_offset + 3 * self._length,
            column_label_offset_length,
            fmt="h",
            cache=self._cache,
        )

        label_len = self._read_byte.read(
            offset + column_label_length_offset + 3 * self._length,
            column_label_length_length,
            fmt="h",
            cache=self._cache,
        )

        label_names = self.column_names_strings[label_idx]
        column_label = label_names[label_start : label_start + label_len]
        format_names = self.column_names_strings[format_idx]
        column_format = format_names[format_start : format_start + format_len]

        current_column_number = len(self.columns)

        self.columns.append(
            Column(
                col_id=current_column_number,
                name=self.column_names[current_column_number],
                label=column_label,
                format=column_format,
                type=self.column_types[current_column_number],
                length=self.column_data_lengths[current_column_number],
            )
        )

    def _process_meta_page(self):
        for i in range(self._meta_page.page_subheaders_count):
            pointer = self._get_pointer_page(index=i)
            if not pointer.length:
                continue

            if pointer.compression != truncated_subheader_id:
                subheader_signature = self._read_byte.read(
                    pointer.offset,
                    self._length,
                    cache=self._cache,
                )

                subheader_index = self._get_subheader_class(
                    subheader_signature, pointer.compression, pointer.type
                )
                if subheader_index is not None:
                    if subheader_index != SASIndex.data_subheader_index:
                        match subheader_index:
                            case SASIndex.row_size_index:
                                self._row_size_subheader(pointer.offset)
                            case SASIndex.column_size_index:
                                self._column_size_subheader(pointer.offset)
                            case SASIndex.column_text_index:
                                self._column_text_subheader(pointer.offset)
                            case SASIndex.column_name_index:
                                self._column_name_subheader(pointer.offset)
                            case SASIndex.column_attributes_index:
                                self._column_attributes_subheader(
                                    pointer.offset, pointer.length
                                )
                            case SASIndex.format_and_label_index:
                                self._format_and_label_subheader(pointer.offset)
                            case _:
                                continue
                    else:
                        self.pointer_page.append(pointer)

    def _start_meta_page(self):
        self._read_meta_page()
        if self._meta_page.page_type in page_meta_mix_amd:
            self._process_meta_page()

    def _parse_metadata(self):
        for i in range(1, self.properties.page_count):
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
        self.meta_columns = SasReadMetaPage(
            byte_file=self._byte_file, properties=self.metadata_file
        )
        self._read_byte = ConvertByte(properties=self.header.properties)

        self._cache_page = None
        self._current_page = None

        self.read_lines()

    @staticmethod
    def _read_sas7bdat(path: str):
        with open(path, "rb") as f:
            result = f.read()
        return result

    def _data_subheader(self, offset, length):
        row_elements = []
        if (
            self.header.properties.compression
            and length < self.header.properties.row_length
        ):
            source = self._cache_page
        else:
            source = self._cache_page

        for i in range(self.header.properties.column_count):
            length = self.meta_columns.column_data_lengths[i]
            if length == 0:
                break

            start = offset + self.meta_columns.column_data_offsets[i]
            end = offset + self.meta_columns.column_data_offsets[i] + length
            temp = source[start:end]
            if self.meta_columns.columns[i].type == "number":
                if self.meta_columns.column_data_lengths[i] <= 2:
                    row_elements.append(
                        self._read_byte.read(0, length, fmt="h", cache=temp)
                    )
                else:
                    fmt = self.meta_columns.columns[i].format
                    if not fmt:
                        ...
                    else:
                        row_elements.append(
                            self._read_byte.read(0, length, fmt="d", cache=temp)
                        )

            else:  # string
                row_elements.append(
                    self._read_byte.read(0, length, fmt="s", cache=temp)
                ).decode(self.header.properties.encode, errors="replace")
            return row_elements

    def read_lines(self):
        bit_offset = self.meta_columns.get_page_bit_offset
        subheader_pointer_length = self.meta_columns.get_subheader_pointer_length()
        row_count = self.header.properties.row_count
        current_row_in_file_index = 0
        current_row_on_page_index = 0

        if self._cache_page is None:
            self._cache_page = self._read_byte.read(
                self.header.properties.header_size,
                self.header.properties.page_size,
                cache=self._byte_file,
            )
        for i in range(0, row_count):
            current_row_in_file_index += 1
            try:
                current_page_type = self.meta_columns.get_metadata_pages()[i].page_type
                pointer_page = self.meta_columns.pointer_page[i]
                res = self._data_subheader(pointer_page.offset, pointer_page.length)
                print(res)

            except IndexError:
                continue

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
