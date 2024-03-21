"""
This type stub file was generated by pyright.
"""

import dataclasses
import enum
import gtirb
import mcasm
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, TypeVar, Union
from typing_extensions import ParamSpec, override
from .._auxdata import CFIDirectiveType
from ..assembly import X86Syntax
from ..dwarf import cfi
from ..utils import OffsetMapping

if gtirb.version.PROTOBUF_VERSION < 4:
    ...
else:
    ...
@dataclasses.dataclass
class Diagnostic:
    """
    A diagnostic issued while assembling input.
    """
    kind: Kind
    message: str
    lineno: Optional[int]
    offset: Optional[int]
    Kind = mcasm.mc.Diagnostic.Kind


DiagnosticCallback = Callable[[Diagnostic], bool]
_StreamerClass = TypeVar("_StreamerClass", bound=Union["_SymbolCreator", "_Streamer"])
_RetT = TypeVar("_RetT")
_ParamsT = ParamSpec("_ParamsT")
_convert_errors = ...
class AssemblerError(Exception):
    """
    Base class for assembler errors that can be associated with the input
    assembly.
    """
    def __init__(self, message: str, lineno: Optional[int] = ..., offset: Optional[int] = ...) -> None:
        ...
    


class AsmSyntaxError(AssemblerError):
    """
    An error was encountered parsing the assembly.
    """
    ...


class UndefSymbolError(AssemblerError):
    """
    A symbol was referenced that was not defined.
    """
    ...


class UnsupportedAssemblyError(AssemblerError):
    """
    The assembly is valid but uses a feature not supported by the Assembler
    class.
    """
    ...


class MultipleDefinitionsError(AssemblerError):
    """
    A symbol was defined multiple times.
    """
    ...


class IgnoredCFIDirectiveWarning(Warning):
    """
    A CFI directive was ignored. Deprecated and no longer issued.
    """
    ...


class IgnoredSymverDirectiveWarning(Warning):
    """
    A .symver directive was ignored.
    """
    ...


class Assembler:
    """
    Assembles chunks of assembly, creating a control flow graph and other
    GTIRB structures as it goes.
    """
    @dataclasses.dataclass
    class Target:
        """
        A description of the assembler's target.
        """
        isa: gtirb.Module.ISA
        file_format: gtirb.Module.FileFormat
        binary_type: List[str]
        is_elf_dynamic: bool
        symbol_lookup: Callable[[str], Iterator[gtirb.Symbol]] = ...
    
    
    class ModuleTarget(Target):
        """
        A target that references an existing module, with the intent being
        that the assembler result will be compatible with this module.
        """
        def __init__(self, module: gtirb.Module, detached: bool = ...) -> None:
            ...
        
    
    
    def __init__(self, target: Union[gtirb.Module, Target], *, diagnostic_callback: Optional[DiagnosticCallback] = ..., temp_symbol_suffix: Optional[str] = ..., trivially_unreachable: bool = ..., allow_undef_symbols: bool = ..., implicit_cfi_procedure: bool = ..., ignore_symver_directives: bool = ...) -> None:
        """
        :param target: The module the patch will be inserted into or a Target
                       object describing the target to assemble for.
        :param diagnostic_callback: A callable invoked when there is a
               Diagnostic issued. If the diagnostic's kind is an error,
               returning False from the callback will result in it being
               raised as an exception (the same behavior as when this callback
               is not specified).
        :param temp_symbol_suffix: A suffix to use for local symbols that are
               considered temporary. Passing in a unique suffix to each
               assembler that targets the same module allows the same assembly
               to be used each time without worrying about duplicate symbol
               names.
        :param trivially_unreachable: Is the entry block of the patch
                                      obviously unreachable? For example,
                                      inserting after a ret instruction.
        :param allow_undef_symbols: Allows the assembly to refer to undefined
                                    symbols. Such symbols will be created and
                                    set to refer to a proxy block.
        :param implicit_cfi_procedure: Treat the assembly as implicitly being
                                       in a CFI procedure.
        :param ignore_symver_directives: Ignore symver directives instead of
                                         issuing an error.
        """
        ...
    
    def assemble(self, asm: str, x86_syntax: X86Syntax = ...) -> bool:
        """
        Assembles additional assembly, continuing where the last call to
        assemble left off.
        """
        ...
    
    def finalize(self) -> Result:
        """
        Finalizes the assembly contents and returns the result.
        """
        ...
    
    @dataclasses.dataclass
    class Result:
        """
        The result of assembling an assembly patch.
        """
        class DataType(str, enum.Enum):
            ULEB128 = ...
            SLEB128 = ...
            String = ...
            ASCII = ...
        
        
        @dataclasses.dataclass
        class CFIPointer:
            encoding: int
            symbol: gtirb.Symbol
            ...
        
        
        @dataclasses.dataclass
        class CFIProcedure:
            personality: Optional[Assembler.Result.CFIPointer] = ...
            lsda: Optional[Assembler.Result.CFIPointer] = ...
            return_column: Optional[int] = ...
            start_offset: Optional[gtirb.Offset] = ...
            end_offset: Optional[gtirb.Offset] = ...
            instructions: OffsetMapping[List[cfi.Instruction]] = ...
            is_implicit: bool = ...
        
        
        @dataclasses.dataclass
        class Section:
            name: str
            flags: Set[gtirb.Section.Flag] = ...
            data: bytes = ...
            blocks: List[gtirb.ByteBlock] = ...
            symbolic_expressions: Dict[int, gtirb.SymbolicExpression] = ...
            symbolic_expression_sizes: Dict[int, int] = ...
            alignment: Dict[gtirb.ByteBlock, int] = ...
            image_type: int = ...
            image_flags: int = ...
            block_types: Dict[gtirb.DataBlock, Assembler.Result.DataType] = ...
            line_map: OffsetMapping[int] = ...
            cfi_procedures: List[Assembler.Result.CFIProcedure] = ...
        
        
        @dataclasses.dataclass
        class ElfSymbolAttributes:
            type: str = ...
            binding: str = ...
            visibility: str = ...
        
        
        target: Assembler.Target
        sections: Dict[str, Section]
        cfg: gtirb.CFG = ...
        symbols: List[gtirb.Symbol] = ...
        proxies: Set[gtirb.ProxyBlock] = ...
        elf_symbol_attributes: Dict[gtirb.Symbol, ElfSymbolAttributes] = ...
        @property
        def text_section(self) -> Section:
            ...
        
        def create_cfi_directives(self) -> OffsetMapping[List[CFIDirectiveType]]:
            """
            Creates the cfiDirectives aux data table for the result.
            """
            ...
        
        def create_ir(self) -> gtirb.IR:
            """
            Creates a new GTIRB IR with the contents of this result.
            """
            ...
        
    
    


@dataclasses.dataclass
class _State:
    """
    All of the state that the assembler accumulates across calls to assemble
    and is used by the streamer classes.
    """
    target: Assembler.Target
    diagnostic_callback: DiagnosticCallback
    temp_symbol_suffix: Optional[str]
    trivially_unreachable: bool
    allow_undef_symbols: bool
    implicit_cfi_procedure: bool
    ignore_symver_directives: bool
    had_error: bool = ...
    cfg: gtirb.CFG = ...
    local_symbols: Dict[str, gtirb.Symbol] = ...
    proxies: Set[gtirb.ProxyBlock] = ...
    optional_current_section: Optional[Assembler.Result.Section] = ...
    sections: Dict[str, Assembler.Result.Section] = ...
    blocks_with_code: Set[gtirb.ByteBlock] = ...
    elf_symbol_attributes: Dict[gtirb.Symbol, Assembler.Result.ElfSymbolAttributes] = ...
    block_types: Dict[gtirb.ByteBlock, Assembler.Result.DataType] = ...
    @property
    def text_section(self) -> Assembler.Result.Section:
        ...
    
    @property
    def current_cfi_procedure(self) -> Optional[Assembler.Result.CFIProcedure]:
        ...
    
    @property
    def current_section(self) -> Assembler.Result.Section:
        ...
    
    @property
    def current_offset(self) -> gtirb.Offset:
        ...
    
    @property
    def current_block(self) -> gtirb.CodeBlock:
        ...
    
    def issue_diagnostic(self, diag: Diagnostic) -> bool:
        ...
    


class _SymbolCreator(mcasm.Streamer):
    """
    A streamer that just takes care of precreating defined symbols.
    """
    def __init__(self, state: _State) -> None:
        ...
    
    @_convert_errors
    def emit_label(self, state: mcasm.ParserState, symbol: mcasm.mc.Symbol, loc: mcasm.mc.SourceLocation) -> None:
        ...
    
    @_convert_errors
    def emit_assignment(self, state: mcasm.ParserState, symbol: mcasm.mc.Symbol, value: mcasm.mc.Expr) -> None:
        ...
    


class _Streamer(mcasm.Streamer):
    """
    Handles streamer callbacks and generates GTIRB IR as needed.
    """
    _ELF_VARIANT_KINDS: Dict[mcasm.mc.SymbolRefExpr.VariantKind, Set[gtirb.SymbolicExpression.Attribute],] = ...
    _ELF_BINDINGS = ...
    _ELF_VISIBILITIES = ...
    _ELF_TYPES = ...
    def __init__(self, state: _State) -> None:
        ...
    
    @_convert_errors
    def emit_label(self, state: mcasm.ParserState, symbol: mcasm.mc.Symbol, loc: mcasm.mc.SourceLocation) -> None:
        ...
    
    @_convert_errors
    def change_section(self, state: mcasm.ParserState, section: mcasm.mc.Section, subsection: Optional[mcasm.mc.Expr]) -> None:
        ...
    
    @_convert_errors
    def emit_instruction(self, state: mcasm.ParserState, inst: mcasm.mc.Instruction, data: bytes, fixups: List[mcasm.mc.Fixup]) -> None:
        ...
    
    @_convert_errors
    def emit_value_impl(self, state: mcasm.ParserState, value: mcasm.mc.Expr, size: int, loc: mcasm.mc.SourceLocation) -> None:
        ...
    
    @_convert_errors
    def emit_uleb128_value(self, state: mcasm.ParserState, value: mcasm.mc.Expr) -> None:
        ...
    
    @_convert_errors
    def emit_sleb128_value(self, state: mcasm.ParserState, value: mcasm.mc.Expr) -> None:
        ...
    
    @_convert_errors
    def emit_bytes(self, state: mcasm.ParserState, data: bytes) -> None:
        ...
    
    @_convert_errors
    def emit_int_value(self, state: mcasm.ParserState, value: int, size: int) -> None:
        ...
    
    @_convert_errors
    def emit_value_fill(self, state: mcasm.ParserState, num_bytes: mcasm.mc.Expr, fill_value: int, loc: mcasm.mc.SourceLocation) -> None:
        ...
    
    @_convert_errors
    def emit_value_to_alignment(self, state: mcasm.ParserState, byte_alignment: int, value: int, value_size: int, max_bytes_to_emit: int) -> None:
        ...
    
    @_convert_errors
    def emit_code_alignment(self, state: mcasm.ParserState, byte_alignment: int, max_bytes_to_emit: int) -> None:
        ...
    
    @_convert_errors_and_return(True)
    def emit_symbol_attribute(self, state: mcasm.ParserState, symbol: mcasm.mc.Symbol, attribute: mcasm.mc.SymbolAttr) -> bool:
        ...
    
    @_convert_errors
    @override
    def emit_cfi_start_proc_impl(self, state: mcasm.ParserState, frame: mcasm.mc.DwarfFrameInfo) -> None:
        ...
    
    @_convert_errors
    @override
    def emit_cfi_end_proc_impl(self, state: mcasm.ParserState, cur_frame: mcasm.mc.DwarfFrameInfo) -> None:
        ...
    
    @_convert_errors
    @override
    def emit_cfi_adjust_cfa_offset(self, state: mcasm.ParserState, adjustment: int) -> None:
        ...
    
    @_convert_errors
    @override
    def emit_cfi_def_cfa(self, state: mcasm.ParserState, register: int, offset: int) -> None:
        ...
    
    @_convert_errors
    @override
    def emit_cfi_def_cfa_offset(self, state: mcasm.ParserState, offset: int) -> None:
        ...
    
    @_convert_errors
    @override
    def emit_cfi_def_cfa_register(self, state: mcasm.ParserState, register: int) -> None:
        ...
    
    @_convert_errors
    @override
    def emit_cfi_escape(self, state: mcasm.ParserState, values: bytes) -> None:
        ...
    
    @_convert_errors
    @override
    def emit_cfi_lsda(self, state: mcasm.ParserState, sym: mcasm.mc.Symbol, encoding: int) -> None:
        ...
    
    @_convert_errors
    @override
    def emit_cfi_offset(self, state: mcasm.ParserState, register: int, offset: int) -> None:
        ...
    
    @_convert_errors
    @override
    def emit_cfi_personality(self, state: mcasm.ParserState, sym: mcasm.mc.Symbol, encoding: int) -> None:
        ...
    
    @_convert_errors
    @override
    def emit_cfi_register(self, state: mcasm.ParserState, register_1: int, register_2: int) -> None:
        ...
    
    @_convert_errors
    @override
    def emit_cfi_rel_offset(self, state: mcasm.ParserState, register: int, offset: int) -> None:
        ...
    
    @_convert_errors
    @override
    def emit_cfi_remember_state(self, state: mcasm.ParserState) -> None:
        ...
    
    @_convert_errors
    def emit_cfi_restore(self, state: mcasm.ParserState, register: int) -> None:
        ...
    
    @_convert_errors
    @override
    def emit_cfi_restore_state(self, state: mcasm.ParserState) -> None:
        ...
    
    @_convert_errors
    @override
    def emit_cfi_return_column(self, state: mcasm.ParserState, register: int) -> None:
        ...
    
    @_convert_errors
    @override
    def emit_cfi_same_value(self, state: mcasm.ParserState, register: int) -> None:
        ...
    
    @_convert_errors
    @override
    def emit_cfi_undefined(self, state: mcasm.ParserState, register: int) -> None:
        ...
    
    def diagnostic(self, state: mcasm.ParserState, diag: mcasm.mc.Diagnostic) -> None:
        ...
    
    @_convert_errors
    def unhandled_event(self, name: str, base_impl: Any, *args: Any, **kwargs: Any) -> Any:
        ...
    

