"""
This type stub file was generated by pyright.
"""

import contextlib
import gtirb
from typing import Iterator

@contextlib.contextmanager
def prepare_for_rewriting(module: gtirb.Module, nop: bytes) -> Iterator[None]:
    """Pre-compute data structure to accelerate rewriting."""
    ...
