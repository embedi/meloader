import re

from idaapi import *
from idc import *
from idautils import *


DISPL_RE = re.compile('\[([a-zA-Z0-9]+),?(.+)?\]')
VOLATILE_REGS = ('r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8')


def trace_mem_access(start, end, regs):
    mem_access = []

    for insn in Heads(start, end):

        dst, value = None, None

        if GetMnem(insn).startswith('ld'):
            dst = GetOpnd(insn, 0)
            if GetOpType(insn, 1) == o_mem:
                value = Dword(GetOperandValue(insn, 1))
                mem_access += [(insn, value, 'r')]
            elif GetOpType(insn, 1) == o_displ:
                _, reg, off, _ = DISPL_RE.split(GetOpnd(insn, 1))
                # print "%08X: %s, %s" % (insn, reg, off)
                try:
                    off = int(off, 16) if off is not None else 0
                    if reg in regs:
                        value = Dword(regs[reg] + off)
                        mem_access += [(insn, regs[reg], 'r')]
                except ValueError:
                    pass

        elif GetMnem(insn).startswith('st'):
            pass

    return mem_access


def _dotrace(start, end, regs, ma, verbose=False):
    if verbose:
        print 'start: 0x%08X, end: 0x%08X, regs: %s' % (start, end, regs)

    for insn in Heads(start, end):

        dst, value = None, None
        add_comm = ''

        if '.' in GetDisasm(insn).split(' ')[0]:
            continue

        if GetMnem(insn) == 'mov':
            dst = GetOpnd(insn, 0)
            if GetOpType(insn, 1) == o_reg and GetOpnd(insn, 1) in regs:
                value = regs[GetOpnd(insn, 1)]
            elif GetOpType(insn, 1) == o_imm:
                value = GetOperandValue(insn, 1)

        elif GetMnem(insn) == 'ld':
            dst = GetOpnd(insn, 0)
            if GetOpType(insn, 1) == o_mem:
                value = Dword(GetOperandValue(insn, 1))
                ma.append((insn, value, 'o'))
            elif GetOpType(insn, 1) == o_displ:
                _, reg, off, _ = DISPL_RE.split(GetOpnd(insn, 1))
                # print "%08X: %s, %s" % (insn, reg, off)
                try:
                    off = int(off, 16) if off is not None else 0
                    if reg in regs:
                        value = Dword(regs[reg] + off)
                        ma.append((insn, regs[reg], 'r'))
                        add_comm = 'xrefto: 0x%08X' % (regs[reg] + off)
                        add_dref(insn, regs[reg] + off, dr_R)
                except ValueError:
                    pass

        elif GetMnem(insn).startswith('st'):
            # value = regs[GetOpnd(insn, 0)]
            if GetOpType(insn, 1) == o_displ:
                _, reg, off, _ = DISPL_RE.split(GetOpnd(insn, 1))
                # print "%08X: %s, %s" % (insn, reg, off)
                try:
                    off = int(off, 16) if off is not None else 0
                    if reg in regs:
                        dst = regs[reg] + off
                        ma.append((insn, regs[reg], 'w'))
                        MakeComm(insn, 'xrefto: 0x%08X' % dst)
                        add_dref(insn, regs[reg] + off, dr_W)
                except ValueError as e:
                    print '0x%08X: %s' % (insn, str(e))

        elif GetMnem(insn) == 'asl':
            dst = GetOpnd(insn, 0)
            if GetOpType(insn, 1) == o_reg and GetOpnd(insn, 1) in regs \
                    and GetOpType(insn, 2) == o_imm:
                value = regs[GetOpnd(insn, 1)] << GetOperandValue(insn, 2)

        elif GetMnem(insn) == 'add':
            dst = GetOpnd(insn, 0)
            if GetOpType(insn, 1) == o_reg and GetOpnd(insn, 1) in regs \
                    and GetOpnd(insn, 2) in regs:
                value = regs[GetOpnd(insn, 1)] + regs[GetOpnd(insn, 2)]
            elif GetOpType(insn, 1) == o_reg and GetOpnd(insn, 1) in regs \
                    and GetOpType(insn, 2) == o_imm:
                value = regs[GetOpnd(insn, 1)] + GetOperandValue(insn, 2)

        elif GetMnem(insn) == 'add2':
            dst = GetOpnd(insn, 0)
            if GetOpType(insn, 1) == o_reg and GetOpnd(insn, 1) in regs \
                    and GetOpnd(insn, 2) in regs:
                value = regs[GetOpnd(insn, 1)] + (regs[GetOpnd(insn, 2)] << 2)
            elif GetOpType(insn, 1) == o_reg and GetOpnd(insn, 1) in regs \
                    and GetOpType(insn, 2) == o_imm:
                value = regs[GetOpnd(insn, 1)] + (GetOperandValue(insn, 2) << 2)

        elif GetMnem(insn) == 'or':
            dst = GetOpnd(insn, 0)
            if (GetOpType(insn, 1) == o_reg and GetOpnd(insn, 1) in regs) and \
                    (GetOpType(insn, 2) == o_reg and GetOpnd(insn, 2) in regs):
                value = regs[GetOpnd(insn, 1)] | regs[GetOpnd(insn, 2)]

        elif GetMnem(insn) == 'sub':
            dst = GetOpnd(insn, 0)
            if GetOpType(insn, 1) == o_reg and GetOpnd(insn, 1) in regs \
                    and GetOpnd(insn, 2) in regs:
                value = regs[GetOpnd(insn, 1)] - regs[GetOpnd(insn, 2)]
            elif GetOpType(insn, 1) == o_reg and GetOpnd(insn, 1) in regs \
                    and GetOpType(insn, 2) == o_imm:
                value = regs[GetOpnd(insn, 1)] - GetOperandValue(insn, 2)                

        elif GetMnem(insn) == 'bset':
            dst = GetOpnd(insn, 0)
            if GetOpType(insn, 1) == o_reg and GetOpnd(insn, 1) in regs \
                    and GetOpType(insn, 2) == o_imm:
                value = regs[GetOpnd(insn, 1)] | (1 << GetOperandValue(insn, 2))

        elif GetMnem(insn) == 'extw':
            dst = GetOpnd(insn, 0)
            if GetOpType(insn, 1) == o_reg and GetOpnd(insn, 1) in regs:
                value = regs[GetOpnd(insn, 1)] & 0xFFFF

        elif is_call_insn(insn):
            reg = GetOpnd(insn, 0)[1:-1]
            print reg
            print regs
            if reg in regs:
                addr = regs[reg]
                MakeComm(insn, Name(addr) if Name(addr) else '0x%08X' % addr)
            for reg in filter(lambda x: x in regs, VOLATILE_REGS):
                del regs[reg]

        if dst is not None and value is not None:
            if getseg(value) and Name(value):
                value_str = Name(value) + ' @ %08X'
            else:
                value_str = '%08X'
            comm = '%s <- %s' % (dst, value_str % value)
            if add_comm:
                comm += '\n' + add_comm
            MakeComm(insn, comm)
            regs[dst] = value
            add_dref(insn, value, dr_O)

        elif dst and dst in regs:
            del regs[dst]

    return regs

def trace_regs(start, end, regs=None, ma=None, verbose=False):
    regs = regs if regs is not None else {}
    ma = ma if ma is not None else []
    return _dotrace(start, end, regs, ma, verbose=verbose)
    # print '\n'.join('%s: %08X' % item for item in _dotrace(start, end, regs).items())


def trace_regs2(start, end, regs=None, ma=None, verbose=False):
    regs = regs if regs is not None else {}
    ma = ma if ma is not None else []
    regs = _dotrace(start, end, regs, ma, verbose=verbose)
    return regs, ma


def trace_regs_man(start=None, end=None, **regs):
    # print 'start: 0x%08X, end: 0x%08X, regs: %s' % (start or SelStart(), end or SelEnd(), regs)
    ma = []
    regs = trace_regs(start or SelStart(), end or SelEnd(), regs, ma, verbose=True)
    for reg, val in regs.items():
        print '\t%4s: 0x%08X' % (reg, val)
    print 'ma:'
    for ea, addr, typ in ma:
        print '\t0x%08X: %s 0x%08X' % (ea, typ, addr)
