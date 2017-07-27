from idaapi import *
from idc import *
from idautils import *


class NotEnoughArguments(Exception):
    pass


def sizeof(typestr):
    _, tp, _ = ParseType(typestr, PT_TYP)
    return SizeOf(tp)


def get_codeblock(ea):
    func = get_func(ea)
    if not func:
        return
    flowchart = FlowChart(func)
    for cb in flowchart:
        if cb.startEA <= ea <= cb.endEA:
            return cb


# def trace_regs(start, end):
#     regs = {}
#
#     # print "_trace_regs(): start = %08X, end = %08X" % (start, end)
#
#     for insn in Heads(start, end):
#         try:
#             if GetMnem(insn) == 'mov':
#                 if GetOpType(insn, 1) == o_reg and GetOpnd(insn, 1) in regs:
#                     regs[GetOpnd(insn, 0)] = regs[GetOpnd(insn, 1)]
#                 elif GetOpType(insn, 1) == o_imm:
#                     regs[GetOpnd(insn, 0)] = GetOperandValue(insn, 1)
#
#             elif GetMnem(insn) == 'ld':
#                 if GetOpType(insn, 1) == o_mem:
#                     regs[GetOpnd(insn, 0)] = Dword(GetOperandValue(insn, 1))
#
#             elif GetMnem(insn) == 'asl':
#                 if GetOpType(insn, 1) == o_reg and GetOpnd(insn, 1) in regs \
#                         and GetOpType(insn, 2) == o_imm:
#                     regs[GetOpnd(insn, 0)] = regs[GetOpnd(insn, 1)] << GetOperandValue(insn, 2)
#
#             elif GetMnem(insn) == 'add':
#                 if GetOpType(insn, 1) == o_reg and GetOpnd(insn, 1) in regs \
#                         and GetOpnd(insn, 2) in regs:
#                     regs[GetOpnd(insn, 0)] = regs[GetOpnd(insn, 1)] + regs[GetOpnd(insn, 1)]
#                 elif GetOpType(insn, 1) == o_reg and GetOpnd(insn, 1) in regs \
#                         and GetOpType(insn, 2) == o_imm:
#                     regs[GetOpnd(insn, 0)] = regs[GetOpnd(insn, 1)] + GetOperandValue(insn, 2)
#
#             elif GetMnem(insn) == 'bset':
#                 if GetOpType(insn, 1) == o_reg and GetOpnd(insn, 1) in regs \
#                         and GetOpType(insn, 2) == o_imm:
#                     regs[GetOpnd(insn, 0)] = regs[GetOpnd(insn, 1)] | (1 << GetOperandValue(insn, 2))
#
#             elif GetOpType(insn, 0) == o_reg and GetOpnd(insn, 0) in regs \
#                     and GetMnem(insn) not in ('cmp', 'stb', 'stw', 'st'):
#                 # print "_trace_regs(): insn = %08X, drop %s" % (insn, GetOpnd(insn, 0))
#                 del regs[GetOpnd(insn, 0)]
#
#         except Exception as e:
#             print 'Caught exception while processing 0x%08X: %s' % (insn, str(e))
#             break
#
#     return regs


def make_name(ea, name):
    return MakeName(ea, SegName(ea) + '_' + name)


def add_seg(start, size, name):
    AddSeg(start, start + size, 0, True, 4, scPub)
    RenameSeg(start, name)
    return getseg(start)


def del_seg(seg_or_ea):
    if isinstance(seg_or_ea, segment_t):
        SegDelete(seg_or_ea.startEA, SEGMOD_KEEP | SEGMOD_SILENT)
    else:
        SegDelete(seg_or_ea, SEGMOD_KEEP | SEGMOD_SILENT)


def hex_or_dec(s):
    return int(s, 16) if s.lower().startswith('0x') else int(s, 10)


def prefixed(prefix, name):
    name = ''.join(name.split('_'))
    prefix = ''.join(prefix.split('_'))
    return ("%s_%s" if prefix else "%s%s") % (prefix, name)


def mirrord(d):
    return dict(((v, k) for k, v in d.iteritems()))


def collect_args(regs, n):
    try:
        return tuple(regs[reg] for reg in ('r%d' % i for i in range(0, n)))
    except KeyError:
        raise NotEnoughArguments


def has_xref_to(func, item, flags=0):
    return GetFunctionName(func) in map(GetFunctionName, (xref.frm for xref in XrefsTo(item, flags)))


def collect_xrefs_to(func, item, flags=0):
    return list(xref for xref in XrefsTo(item) if get_func(xref.frm).startEA == func)
