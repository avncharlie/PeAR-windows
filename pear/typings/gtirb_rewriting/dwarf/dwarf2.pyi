"""
This type stub file was generated by pyright.
"""

from enum import Enum

class CallFrameInstructions(int, Enum):
    nop = ...
    set_loc = ...
    advance_loc1 = ...
    advance_loc2 = ...
    advance_loc4 = ...
    offset_extended = ...
    restore_extended = ...
    undefined = ...
    same_value = ...
    register = ...
    remember_state = ...
    restore_state = ...
    def_cfa = ...
    def_cfa_register = ...
    def_cfa_offset = ...
    def_cfa_expression = ...
    expression = ...
    offset_extended_sf = ...
    def_cfa_sf = ...
    def_cfa_offset_sf = ...
    val_offset = ...
    val_offset_sf = ...
    val_expression = ...
    advance_loc = ...
    offset = ...
    restore = ...
    gnu_window_save = ...
    gnu_args_size = ...
    gnu_negative_offset_extended = ...
    aarch64_negate_ra_state = ...


class ExpressionOperations(int, Enum):
    addr = ...
    deref = ...
    const1u = ...
    const1s = ...
    const2u = ...
    const2s = ...
    const4u = ...
    const4s = ...
    const8u = ...
    const8s = ...
    constu = ...
    consts = ...
    dup = ...
    drop = ...
    over = ...
    pick = ...
    swap = ...
    rot = ...
    xderef = ...
    abs = ...
    and_ = ...
    div = ...
    minus = ...
    mod = ...
    mul = ...
    neg = ...
    not_ = ...
    or_ = ...
    plus = ...
    plus_uconst = ...
    shl = ...
    shr = ...
    shra = ...
    xor = ...
    skip = ...
    bra = ...
    eq = ...
    ge = ...
    gt = ...
    le = ...
    lt = ...
    ne = ...
    lit0 = ...
    lit1 = ...
    lit2 = ...
    lit3 = ...
    lit4 = ...
    lit5 = ...
    lit6 = ...
    lit7 = ...
    lit8 = ...
    lit9 = ...
    lit10 = ...
    lit11 = ...
    lit12 = ...
    lit13 = ...
    lit14 = ...
    lit15 = ...
    lit16 = ...
    lit17 = ...
    lit18 = ...
    lit19 = ...
    lit20 = ...
    lit21 = ...
    lit22 = ...
    lit23 = ...
    lit24 = ...
    lit25 = ...
    lit26 = ...
    lit27 = ...
    lit28 = ...
    lit29 = ...
    lit30 = ...
    lit31 = ...
    reg0 = ...
    reg1 = ...
    reg2 = ...
    reg3 = ...
    reg4 = ...
    reg5 = ...
    reg6 = ...
    reg7 = ...
    reg8 = ...
    reg9 = ...
    reg10 = ...
    reg11 = ...
    reg12 = ...
    reg13 = ...
    reg14 = ...
    reg15 = ...
    reg16 = ...
    reg17 = ...
    reg18 = ...
    reg19 = ...
    reg20 = ...
    reg21 = ...
    reg22 = ...
    reg23 = ...
    reg24 = ...
    reg25 = ...
    reg26 = ...
    reg27 = ...
    reg28 = ...
    reg29 = ...
    reg30 = ...
    reg31 = ...
    breg0 = ...
    breg1 = ...
    breg2 = ...
    breg3 = ...
    breg4 = ...
    breg5 = ...
    breg6 = ...
    breg7 = ...
    breg8 = ...
    breg9 = ...
    breg10 = ...
    breg11 = ...
    breg12 = ...
    breg13 = ...
    breg14 = ...
    breg15 = ...
    breg16 = ...
    breg17 = ...
    breg18 = ...
    breg19 = ...
    breg20 = ...
    breg21 = ...
    breg22 = ...
    breg23 = ...
    breg24 = ...
    breg25 = ...
    breg26 = ...
    breg27 = ...
    breg28 = ...
    breg29 = ...
    breg30 = ...
    breg31 = ...
    regx = ...
    fbreg = ...
    bregx = ...
    piece = ...
    deref_size = ...
    xderef_size = ...
    nop = ...
    push_object_address = ...
    call2 = ...
    call4 = ...
    call_ref = ...

