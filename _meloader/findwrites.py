from idaapi import *
from idc import *
from idautils import *

from kapi import KAPI
from traceregs import trace_regs2


def find_writes(ea):
    for xref in XrefsTo(ea, XREF_ALL):
        cb = _get_codeblock(xref.frm)
        if cb:
            print 'trace_regs2(0x%08X, 0x%08X)' % (xref.frm, cb.endEA)
            regs, ma = trace_regs2(xref.frm, cb.endEA)
            print 'xref.frm: 0x%08x' % xref.frm
            print '\n'.join('\t%s: 0x%08X' % item for item in regs.items())
            print '\n'.join('\t0x%08X: %s 0x%08X' % (ea, typ, addr) for ea, addr, typ in ma)
            if ea not in regs.values():
                yield xref.frm


def _get_codeblock(ea):
    func = get_func(ea)
    if func:
        fc = FlowChart(f=func)
        for cb in fc:
            if cb.startEA <= ea <= cb.endEA:
                return cb