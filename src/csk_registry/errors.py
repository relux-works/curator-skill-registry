"""Shared error bases for the registry service.

Kept free of package imports: both the signing layer (``signing.py``) and
the protocol layer (``protocol.py``) derive errors from
:class:`ProtocolError`, so the base lives here to avoid a
protocol↔signing import cycle.
"""

from __future__ import annotations


class ProtocolError(ValueError):
    """A client-supplied protocol object is malformed."""
