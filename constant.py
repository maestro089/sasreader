from typing import Final
from datetime import datetime


epoch = datetime(1960, 1, 1)


endianness_offset: Final = 37
endianness_length: Final = 1
encoding_offset: Final = 70
encoding_length: Final = 1
align_1_value: Final = 4
date_created_offset: Final = 164
date_created_length: Final = 8
date_modified_offset: Final = 172
date_modified_length: Final = 8

rle_compression: Final = b'SASYZCRL'
rrdc_compression: Final = b'SASYZCR2'

compression_literals = [rle_compression, rrdc_compression]



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
