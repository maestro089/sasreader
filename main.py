import sys
import struct

from dataclasses import dataclass
from typing import Optional 
from constant import *
from datetime import datetime, timedelta


@dataclass
class HeaderMetadata:
    encoding: str = 'utf-8'
    need_byteswap: str | None = None
    date_created: str | None = None
    date_modified: str | None = None

    def __repr__(self):
        return f"""----------------------------------------------
        encoding: {self.encoding}
        need_byteswap: {self.need_byteswap}
        date_created: {self.date_created}
        date_modified: {self.date_modified}
        """


class SasRead:
    def __init__(self, path_file: str):
        self.byte_order = None
        self.need_byteswap = None

        self.byte_file = self._open_file(path_file=path_file)
        self.header_metadata = HeaderMetadata()
        self._read_metadata()
        

    def _open_file(self, path_file: str) -> bytes:
        with open(path_file, 'rb') as f:
            return f.read()
        
    def _read_byte(self, offset: int, length: int, align1: int = 0, align2: int = 0) -> bytes:
        res = self.byte_file[offset + align1:offset + length + align2]
        return res
        
    def _read_metadata(self):
        #Определяем кодировку файла
        encode = ord(self.byte_file[encoding_offset:encoding_offset + encoding_length])
        if encode in encoding_names:
            self.header_metadata.encoding = encoding_names[encode]
        else:
            raise ValueError('Ошиибка в определении кодировки файла')
        
        buf = self._read_byte(endianness_offset, endianness_length)
        if buf == b"\x01":
            fmt = '<%s' % 'd'
            align = align_1_value
            self.header_metadata.need_byteswap = sys.byteorder
        else:
            fmt = '>%s' % 'd'
            align = 0
            self.header_metadata.need_byteswap = sys.byteorder
        
        #Дата создания таблицы
        val = self._read_byte(date_created_offset, date_created_length, align1=align, align2=align)
        val = struct.unpack(str(fmt), val)[0]
        self.header_metadata.date_created = epoch + timedelta(seconds=val)

        #Дата обновления таблицы
        val = self._read_byte(date_modified_offset, date_modified_length, align1=align, align2=align)
        val = struct.unpack(str(fmt), val)[0]
        self.header_metadata.date_modified = epoch + timedelta(seconds=val)


    def header(self):
        return self.header_metadata
        

s = SasRead(path_file='test.sas7bdat')

print(s.header())
    
