from typing import Final
from datetime import datetime

epoch = datetime(1960, 1, 1)

page_bit_offset_x86: Final = 16
page_bit_offset_x64: Final = 32

header_size_offset: Final = 196
header_size_length: Final = 4
subheader_pointer_length_x86 = 12
subheader_pointer_length_x64 = 24

page_type_offset: Final = 0
page_type_length: Final = 2
block_count_offset: Final = 2
block_count_length: Final = 2
subheader_count_offset: Final = 4
subheader_count_length: Final = 2


dataset_offset: Final = 92
dataset_length: Final = 64
file_type_offset: Final = 156
file_type_length: Final = 8

row_length_offset_multiplier: Final = 5
row_count_offset_multiplier: Final = 6
col_count_p1_multiplier: Final = 9
col_count_p2_multiplier: Final = 10
row_count_on_mix_page_offset_multiplier: Final = 15
subheader_pointers_offset: Final = 8
truncated_subheader_id: Final = 1
compressed_subheader_id: Final = 4
compressed_subheader_type: Final = 1
text_block_size_length: Final = 2

rle_compression: Final = b"SASYZCRL"
rdc_compression: Final = b"SASYZCR2"
compression_literals: Final = [rle_compression, rdc_compression]

column_name_pointer_length: Final = 8
column_name_text_subheader_offset: Final = 0
column_name_text_subheader_length: Final = 2
column_name_offset_offset: Final = 2
column_name_offset_length: Final = 2
column_name_length_offset: Final = 4
column_name_length_length: Final = 2
column_data_offset_offset: Final = 8
column_data_length_offset: Final = 8
column_data_length_length: Final = 4
column_type_offset: Final = 14
column_type_length: Final = 1
column_format_text_subheader_index_offset: Final = 22
column_format_text_subheader_index_length: Final = 2
column_format_offset_offset: Final = 24
column_format_offset_length: Final = 2
column_format_length_offset: Final = 26
column_format_length_length: Final = 2
column_label_text_subheader_index_offset: Final = 28
column_label_text_subheader_index_length: Final = 2
column_label_offset_offset: Final = 30
column_label_offset_length: Final = 2
column_label_length_offset: Final = 32
column_label_length_length: Final = 2


# Типы страниц
page_meta_type: Final = 0
page_data_type: Final = 256
page_mix_type: Final = 512
page_amd_type: Final = 1024
page_meta2_type: Final = 16384
page_comp_type: Final = -28672

page_meta_mix_data: Final = [
    page_meta_type,
    page_meta2_type,
    page_data_type,
    page_mix_type,
]

page_size_offset: Final = 200
page_size_length: Final = 4
page_count_offset: Final = 204
page_count_length: Final = 4

endianness_offset: Final = 37
endianness_length: Final = 1
encoding_offset: Final = 70
encoding_length: Final = 1

sas_version_offset: Final = 216
sas_version_length: Final = 8

platform_offset: Final = 39
platform_length: Final = 1

align_1_checker_value: Final = b"3"
align_1_offset: Final = 32
align_1_length: Final = 1
align_1_value: Final = 4
u64_byte_checker_value: Final = b"3"
align_2_offset: Final = 35
align_2_length: Final = 1
align_2_value: Final = 4

date_created_offset: Final = 164
date_created_length: Final = 8
date_modified_offset: Final = 172
date_modified_length: Final = 8


class SASIndex:
    row_size_index: Final = 0
    column_size_index: Final = 1
    subheader_counts_index: Final = 2
    column_text_index: Final = 3
    column_name_index: Final = 4
    column_attributes_index: Final = 5
    format_and_label_index: Final = 6
    column_list_index: Final = 7
    data_subheader_index: Final = 8


subheader_signature_to_index: Final = {
    b"\xf7\xf7\xf7\xf7": SASIndex.row_size_index,
    b"\x00\x00\x00\x00\xf7\xf7\xf7\xf7": SASIndex.row_size_index,
    b"\xf7\xf7\xf7\xf7\x00\x00\x00\x00": SASIndex.row_size_index,
    b"\xf7\xf7\xf7\xf7\xff\xff\xfb\xfe": SASIndex.row_size_index,
    b"\xf6\xf6\xf6\xf6": SASIndex.column_size_index,
    b"\x00\x00\x00\x00\xf6\xf6\xf6\xf6": SASIndex.column_size_index,
    b"\xf6\xf6\xf6\xf6\x00\x00\x00\x00": SASIndex.column_size_index,
    b"\xf6\xf6\xf6\xf6\xff\xff\xfb\xfe": SASIndex.column_size_index,
    b"\x00\xfc\xff\xff": SASIndex.subheader_counts_index,
    b"\xff\xff\xfc\x00": SASIndex.subheader_counts_index,
    b"\x00\xfc\xff\xff\xff\xff\xff\xff": SASIndex.subheader_counts_index,
    b"\xff\xff\xff\xff\xff\xff\xfc\x00": SASIndex.subheader_counts_index,
    b"\xfd\xff\xff\xff": SASIndex.column_text_index,
    b"\xff\xff\xff\xfd": SASIndex.column_text_index,
    b"\xfd\xff\xff\xff\xff\xff\xff\xff": SASIndex.column_text_index,
    b"\xff\xff\xff\xff\xff\xff\xff\xfd": SASIndex.column_text_index,
    b"\xff\xff\xff\xff": SASIndex.column_name_index,
    b"\xff\xff\xff\xff\xff\xff\xff\xff": SASIndex.column_name_index,
    b"\xfc\xff\xff\xff": SASIndex.column_attributes_index,
    b"\xff\xff\xff\xfc": SASIndex.column_attributes_index,
    b"\xfc\xff\xff\xff\xff\xff\xff\xff": SASIndex.column_attributes_index,
    b"\xff\xff\xff\xff\xff\xff\xff\xfc": SASIndex.column_attributes_index,
    b"\xfe\xfb\xff\xff": SASIndex.format_and_label_index,
    b"\xff\xff\xfb\xfe": SASIndex.format_and_label_index,
    b"\xfe\xfb\xff\xff\xff\xff\xff\xff": SASIndex.format_and_label_index,
    b"\xff\xff\xff\xff\xff\xff\xfb\xfe": SASIndex.format_and_label_index,
    b"\xfe\xff\xff\xff": SASIndex.column_list_index,
    b"\xff\xff\xff\xfe": SASIndex.column_list_index,
    b"\xfe\xff\xff\xff\xff\xff\xff\xff": SASIndex.column_list_index,
    b"\xff\xff\xff\xff\xff\xff\xff\xfe": SASIndex.column_list_index,
}

magic_number: Final = (
    b"\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\xc2\xea\x81\x60"
    b"\xb3\x14\x11\xcf\xbd\x92\x08\x00"
    b"\x09\xc7\x31\x8c\x18\x1f\x10\x11"
)

encoding_names: Final = {
    20: "utf-8",
    29: "latin1",
    30: "latin2",
    31: "latin3",
    32: "latin4",
    33: "cyrillic",
    34: "arabic",
    35: "greek",
    36: "hebrew",
    37: "latin5",
    38: "latin6",
    39: "cp874",
    40: "latin9",
    41: "cp437",
    42: "cp850",
    43: "cp852",
    44: "cp857",
    45: "cp858",
    46: "cp862",
    47: "cp864",
    48: "cp865",
    49: "cp866",
    50: "cp869",
    51: "cp874",
    # 52: "",  # not found
    # 53: "",  # not found
    # 54: "",  # not found
    55: "cp720",
    56: "cp737",
    57: "cp775",
    58: "cp860",
    59: "cp863",
    60: "cp1250",
    61: "cp1251",
    62: "cp1252",
    63: "cp1253",
    64: "cp1254",
    65: "cp1255",
    66: "cp1256",
    67: "cp1257",
    68: "cp1258",
    118: "cp950",
    # 119: "",  # not found
    123: "big5",
    125: "gb2312",
    126: "cp936",
    134: "euc_jp",
    136: "cp932",
    138: "shift_jis",
    140: "euc-kr",
    141: "cp949",
    227: "latin8",
    # 228: "", # not found
    # 229: ""  # not found
}
