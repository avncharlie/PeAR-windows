"""
This type stub file was generated by pyright.
"""

import gtirb
import mcasm
from typing import Dict, Set

PLT: gtirb.SymbolicExpression.Attribute = ...
GOT: gtirb.SymbolicExpression.Attribute = ...
LO12: gtirb.SymbolicExpression.Attribute = ...
ELF_VARIANT_KINDS: Dict[mcasm.mc.SymbolRefExpr.VariantKind, Set[gtirb.SymbolicExpression.Attribute]] = ...