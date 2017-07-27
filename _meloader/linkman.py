from itertools import chain

from idaapi import *
from idc import *
from idautils import *

from kapi import KAPI
from traceregs import trace_regs
from misc import *


class CannotResolveImport(Exception):
    pass


class CannotResolveExport(Exception):
    pass


def resolve_import(start, end, known_regs=None, bss=None, verbose=False):
    known_regs = known_regs or {}

    regs = trace_regs(start, end)
    regs.update(known_regs)
    if verbose:
        print 'resolve_import(): start=0x%08X, end=0x%08X, known_regs=%s, bss=%s' \
              % (start, end, known_regs, bss is not None)
        for reg, value in regs.items():
            print '\t%s: 0x%08X' % (reg, value)

    got_args = False
    try:
        it_ctx, it_data, it_len = collect_args(regs, 3)
        got_args = True
    except NotEnoughArguments:
        pass

    if not got_args and bss:
        try:
            it_ctx, it_data = collect_args(regs, 2)
            it_len = _calc_import_table_length(it_data, bss)
            if it_len > 0:
                got_args = True
        except NotEnoughArguments:
            pass

    if not got_args:
        raise CannotResolveImport

    # print "it_len == %d" % it_len

    MakeUnknown(it_data, it_len * sizeof('KAPI_IMPORT_DESCR'), FF_UNK)
    MakeStruct(it_data, 'KAPI_IMPORT_DESCR')
    MakeArray(it_data, it_len)

    # _make_name(it_data, 'ImportDescr')

    imports = {}
    for it_descr in range(it_data,
                          it_data + it_len * sizeof('KAPI_IMPORT_DESCR'),
                          sizeof('KAPI_IMPORT_DESCR')):
        id = Dword(it_descr)
        ptr = Dword(it_descr + 4)
        # print "id: %08X, ptr: %08X" % (id, ptr)

        MakeDword(ptr)
        imports[id] = ptr

        # if verbose:
        #     print 'resolve_export(): id=0x%08X, table_addr=0x%08X'

        MakeComm(ptr, str(id))

    return imports


def resolve_export(start, end, known_regs=None, verbose=False):
    known_regs = known_regs or {}

    regs = trace_regs(start, end)
    regs.update(known_regs)

    if verbose:
        print 'resolve_export(): start=0x%08X, end=0x%08X, known_regs=%s' \
              % (start, end, known_regs)
        for reg, value in regs.items():
            print '\t%s: 0x%08X' % (reg, value)

    try:
        et_ctx, et_data, et_len = collect_args(regs, 3)
    except NotEnoughArguments:
        raise CannotResolveExport

    MakeUnknown(et_data, et_len * sizeof('KAPI_EXPORT_DESCR'), FF_UNK)
    MakeStruct(et_data, 'KAPI_EXPORT_DESCR')
    MakeArray(et_data, et_len)

    exports = {}

    # if verbose:
    #     print 'resolve_export(): range(0x%08X, 0x%08X, %d)' % \
    #           (et_data, et_data + et_len * sizeof('KAPI_EXPORT_DESCR'), sizeof('KAPI_EXPORT_DESCR'))

    for et_descr in range(et_data,
                          et_data + et_len * sizeof('KAPI_EXPORT_DESCR'),
                          sizeof('KAPI_EXPORT_DESCR')):
        id = Dword(et_descr)
        # print "id: %08X" % id
        table_addr = Dword(et_descr + 4)
        length = Word(table_addr + 2) >> 4
        # print "%08X: %08X" % (table_addr, length)
        MakeUnknown(table_addr, 4 + length, FF_UNK)
        MakeStructEx(table_addr, 4 + length, 'KAPI_EXPORT_TABLE')

        if verbose:
            print 'resolve_export(): id=0x%08X, table_addr=0x%08X'

        exports[id] = table_addr

    return exports


def resolve_import_man(start=None, end=None, **regs):
    print 'start: 0x%08X, end: 0x%08X, regs: %s' % (start or SelStart(), end or SelEnd(), regs)
    print '%08X: %08X' % resolve_import(start or SelStart(), end or SelEnd(), regs, verbose=True)


def resolve_export_man(start=None, end=None, **regs):
    print 'start: 0x%08X, end: 0x%08X, regs: %s' % (start or SelStart(), end or SelEnd(), regs)
    print '%08X: %08X' % resolve_export(start or SelStart(), end or SelEnd(), regs, verbose=True)


def _calc_import_table_length(addr, bss):
    if not bss:
        return 0
    length = 0
    while True:
        if getseg(Dword(addr + 4)) != bss:
            break
        length += 1
        addr += 8
    return length