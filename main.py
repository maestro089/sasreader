from dataclasses import dataclass
from datetime import timedelta
from copy import copy
from typing import Union

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
    pointer = None
    cache = None


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


class Decompressor(object):

    def decompress_row(self, offset, length, result_length, page):
        raise NotImplementedError

    @staticmethod
    def to_ord(int_or_str):
        if isinstance(int_or_str, int):
            return int_or_str
        return ord(int_or_str)


class RLEDecompressor(Decompressor):
    """
    Decompresses data using the Run Length Encoding algorithm
    """

    def decompress_row(self, offset, length, result_length, page):
        b = self.to_ord
        result = bytearray()
        i = 0

        while i < length:
            current_byte = b(page[offset + i])
            control_byte = current_byte & 0xF0
            end_of_first_byte = current_byte & 0x0F

            if control_byte == 0x00:
                if i != length - 1:
                    count_of_bytes_to_copy = (
                        (b(page[offset + i + 1]) & 0xFF) + 64 + end_of_first_byte * 256
                    )
                    start = offset + i + 2
                    end = start + count_of_bytes_to_copy
                    result.extend(page[start:end])
                    i += count_of_bytes_to_copy + 2

            elif control_byte == 0x40:
                copy_counter = end_of_first_byte * 16 + (b(page[offset + i + 1]) & 0xFF)
                repeated_byte = page[offset + i + 2]
                result.extend([repeated_byte] * (copy_counter + 18))
                i += 3

            elif control_byte in (0x60, 0x70):
                count = end_of_first_byte * 256 + (b(page[offset + i + 1]) & 0xFF) + 17
                fill_byte = 0x20 if control_byte == 0x60 else 0x00
                result.extend([fill_byte] * count)
                i += 2

            elif 0x80 <= control_byte <= 0xB0:
                # Обработка диапазонов 0x80–0xB0 с разной базой
                base_values = {0x80: 1, 0x90: 17, 0xA0: 33, 0xB0: 49}
                base = base_values[control_byte]
                count_of_bytes_to_copy = min(end_of_first_byte + base, length - (i + 1))
                start = offset + i + 1
                end = start + count_of_bytes_to_copy
                result.extend(page[start:end])
                i += count_of_bytes_to_copy + 1

            elif control_byte == 0xC0:
                repeated_byte = page[offset + i + 1]
                result.extend([repeated_byte] * (end_of_first_byte + 3))
                i += 2  # +2: байт управления и байт значения

            elif control_byte in (0xD0, 0xE0, 0xF0):
                # Обработка заполнителей с разными значениями
                fill_values = {0xD0: 0x40, 0xE0: 0x20, 0xF0: 0x00}
                fill_byte = fill_values[control_byte]
                result.extend([fill_byte] * (end_of_first_byte + 2))
                i += 1

            else:
                # Неизвестный control_byte — пропускаем байт
                i += 1

        return bytes(result)


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
            if length < 8:
                if self._properties.endianness == "little":
                    res_cache = b"".join([b"\x00" * (8 - length), res_cache])
                else:
                    res_cache += b"\x00" * (8 - length)

            result = struct.unpack(str(_fmt), res_cache)[0]
        elif fmt == "s":
            val = res_cache.strip(b"\x00")
            val = struct.unpack(_fmt, val)[0].decode()
            result = val.strip()
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
        self.properties.encode = (
            encoding_names[val] if val in encoding_names else "utf-8"
        )

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

    def get_metadata_pages(self) -> list:
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
            if self._meta_page.page_type in page_meta_mix_amd:
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

                            val = copy(pointer)
                            self.pointer_page.append(val)

        self._meta_page.pointer = copy(self.pointer_page)
        self.pointer_page = []
        self._meta_page.cache = self._cache

        self._metadata_pages.append(copy(self._meta_page))

    def _start_meta_page(self):
        self._read_meta_page()
        self._process_meta_page()

    def _parse_metadata(self):
        for i in range(1, self.properties.page_count + 1):
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
        # Кэшируем часто используемые атрибуты
        header_props = self.header.properties
        meta_columns = self.meta_columns
        column_count = header_props.column_count
        column_data_lengths = meta_columns.column_data_lengths
        column_data_offsets = meta_columns.column_data_offsets
        columns = meta_columns.columns

        # Определяем источник данных
        if header_props.compression and length < header_props.row_length:
            decompressor = RLEDecompressor()
            source = decompressor.decompress_row(
                offset=offset,
                length=length,
                result_length=header_props.row_length,
                page=self._cache_page,
            )
            offset = 0
        else:
            source = self._cache_page

        row_elements = []

        # Предварительно вычисляем все диапазоны для ускорения доступа
        ranges = [
            (
                offset + column_data_offsets[i],
                offset + column_data_offsets[i] + column_data_lengths[i],
            )
            for i in range(column_count)
            if column_data_lengths[i] > 0
        ]

        for i, (start, end) in enumerate(ranges):
            temp = source[start:end]
            column = columns[i]

            if column.type == "number":
                # Унифицированная обработка числовых данных
                if column_data_lengths[i] <= 2:
                    value = self._read_byte.read(
                        0, column_data_lengths[i], fmt="h", cache=temp
                    )
                else:
                    # Всегда используем формат 'd' для чисел > 2 байт
                    value = self._read_byte.read(
                        0, column_data_lengths[i], fmt="d", cache=temp
                    )
            else:  # string
                value = self._read_byte.read(
                    0, column_data_lengths[i], fmt="s", cache=temp
                )

            row_elements.append(value)

        return row_elements

    def _calculate_row_offset(self, page, i, is_mixed=False):
        """Вычисляет смещение для i‑й строки на странице."""
        meta_columns = self.meta_columns
        base_offset = (
            meta_columns.get_page_bit_offset()
            + subheader_pointers_offset
            + page.page_subheaders_count * meta_columns.get_subheader_pointer_length()
        )

        if is_mixed:
            align_correction = base_offset % 8
            base_offset += align_correction

        return base_offset + i * self.header.properties.row_length

    def read_lines(self):
        for page in self.meta_columns.get_metadata_pages():
            self._cache_page = page.cache

            if page.page_type == page_meta_type:
                for pointer in page.pointer:
                    row = self._data_subheader(pointer.offset, pointer.length)
                    yield row
            elif page.page_type in page_mix_type:
                for i in range(0, page.page_block_count - page.page_subheaders_count):
                    align_correction = (
                        self.meta_columns.get_page_bit_offset()
                        + subheader_pointers_offset
                        + page.page_subheaders_count
                        * self.meta_columns.get_subheader_pointer_length()
                    ) % 8

                    offset = (
                        self.meta_columns.get_page_bit_offset()
                        + subheader_pointers_offset
                        + align_correction
                        + page.page_subheaders_count
                        * self.meta_columns.get_subheader_pointer_length()
                        + i * self.header.properties.row_length
                    )

                    row = self._data_subheader(
                        offset, self.header.properties.row_length
                    )
                    yield row
            elif page.page_type == page_data_type:
                for i in range(0, page.page_block_count - page.page_subheaders_count):
                    row = self._data_subheader(
                        self.meta_columns.get_page_bit_offset()
                        + subheader_pointers_offset
                        + i * self.header.properties.row_length,
                        self.header.properties.row_length,
                    )
                    yield row

    def test(self):
        return self.header.properties


# res = SasReader(path="../noairflow/gss2024.sas7bdat")
res = SasReader(path="../noairflow/cars.sas7bdat")


def test():
    k = []
    for i in res.read_lines():
        print(i)


import cProfile

cProfile.run("test()")
