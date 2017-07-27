import sys
import hashlib

from construct import *

from .unhuffme import unhuff


class MeHuffmanModuleConstruct(Construct):

    def _parse(self, stream, context):
        lut = context._._.lut
        start = context.base_addr
        end = start + context.size_uncompressed
        va_base = lut.addr_base + 0x10000000

        oldpos = stream.tell()
        stream.seek(lut.huff_start)
        mdata = stream.read(lut.huff_len + 1024)
        stream.seek(oldpos)

        scratch = b''

        for pos in range(start, end, lut.page_size):

            i = ((pos - va_base) & 0xFFFFFFFF) / lut.page_size
            if i >= lut.chunk_count or lut.entries[i].flags == 'EMPTY':
                continue

            huff = mdata[lut.entries[i].addr - lut.huff_start:]
            cflags = lut.entries[i].flags

            out = unhuff(huff, lut.page_size, cflags, 9)
            if not out:
                raise Exception

            outsize = lut.page_size
            if end - pos < outsize:
                outsize = end - pos
            scratch += out[:outsize]

        sha256 = hashlib.sha256()
        sha256.update(scratch)
        hash = sha256.digest()
        if hash != context.hash[::-1]:
            open(context.name, 'wb').write(scratch)
            raise ConstructError('Hash does not match: %s' % context.name)

        return scratch

    def _sizeof(self, context):
        return 0


class MeLzmaModuleConstruct(Construct):

    def _parse(self, stream, context):
        oldpos = stream.tell()
        stream.seek(context._._._.offset + context.offset)
        compressed = stream.read(context.size_compressed)
        stream.seek(oldpos)

        if sys.platform.startswith('linux'):
            cmd = '7z x -so %s >%s 2>/dev/null'
        elif sys.platform.startswith('win'):
            cmd = '"C:\\Program Files\\7-zip\\7z.exe" x -so %s >%s 2>Z:\\tmp\\7z.log'
        else:
            raise Exception('Do not know how to decompress LZMA on %s' % sys.platform)

        import tempfile
        import os
        infile = tempfile.mktemp()
        open(infile, 'wb').write(compressed)
        outfile = tempfile.mktemp()
        if os.system(cmd % (infile, outfile)) != 0:
            raise ConstructError('7z has failed')
        decompressed = open(outfile, 'rb').read()
        os.remove(infile)
        os.remove(outfile)

        sha256 = hashlib.sha256()
        sha256.update(decompressed)
        hash = sha256.digest()
        if hash != context.hash[::-1]:
            open(context.name, 'wb').write(decompressed)
            raise ConstructError('Hash does not match: %s' % context.name)

        return decompressed

    def _sizeof(self, context):
        return 0


class MePlainModuleConstruct(Construct):

    def _parse(self, stream, context):
        oldpos = stream.tell()
        stream.seek(context._._._.offset + context.offset)
        data = stream.read(context.size_compressed)
        stream.seek(oldpos)

        sha256 = hashlib.sha256()
        sha256.update(data)
        hash = sha256.digest()
        if hash != context.hash[::-1]:
            open(context.name, 'wb').write(data)
            raise ConstructError('Hash does not match: %s' % context.name)

        return data

    def _sizeof(self, context):
        return 0


MeHuffmanModule = MeHuffmanModuleConstruct('module')
MeLzmaModule = MeLzmaModuleConstruct('module')
MePlainModule = MePlainModuleConstruct('module')
