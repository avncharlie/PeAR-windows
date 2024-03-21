"""
This type stub file was generated by pyright.
"""

import dataclasses
import gtirb
import gtirb_functions
from typing import Callable, List, Optional
from .assembly import Constraints, Register

@dataclasses.dataclass
class InsertionContext:
    """
    A concrete location to insert code at, plus helper utilities.
    """
    module: gtirb.Module
    function: Optional[gtirb_functions.Function]
    block: gtirb.ByteBlock
    offset: int
    stack_adjustment: Optional[int] = ...
    scratch_registers: List[Register] = ...
    def decorate_extern_symbol(self, name: str) -> str:
        ...
    
    def temporary_label(self, name: str) -> str:
        """
        Creates a temporary label based off of the given base name.
        """
        ...
    


def patch_constraints(*args, **kwargs): # -> Callable[..., Any]:
    """
    Associates a Constraints object with a function that is meant to be used
    as a Patch (see Patch.from_function). The arguments to the decorator are
    used when constructing the Constraints object.
    """
    ...

class Patch:
    """
    A chunk of assembly code to be inserted into a program, along with its
    constraints.
    """
    def __init__(self, constraints: Constraints) -> None:
        ...
    
    def get_asm(self, insertion_context: InsertionContext) -> Optional[str]:
        """
        Returns the assembly string for the patch.

        If the assembly string references symbols, the GTIRB module's symbol
        table will be updated as needed and symbolic expressions will be
        created.

        If None is returned, no insertion takes place.

        :param insertion_context: The concrete location where the code will be
                                  inserted.
        """
        ...
    
    @classmethod
    def from_function(cls, func: Callable, constraints: Optional[Constraints] = ...): # -> FuncPatch:
        """
        Creates a Patch from a callable that has been decorated with the
        @patch_constraints decorator.
        """
        class FuncPatch(Patch):
            ...
        
        
    

