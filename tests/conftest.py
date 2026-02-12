# SPDX-License-Identifier: MIT
# See LICENSE.md for full license text

"""
Pytest configuration and fixtures for urtypes tests.

This module injects test-only equality methods into production classes,
keeping the production code clean while enabling comprehensive testing.
"""

import pytest
from urtypes.registry import RegistryItem
from urtypes.bytes import Bytes
from urtypes.cbor.data import DataItem, Tagging
from urtypes.crypto.bip39 import BIP39
from urtypes.crypto.coin_info import CoinInfo
from urtypes.crypto.keypath import Keypath, PathComponent
from urtypes.crypto.account import Account
from urtypes.crypto.ec_key import ECKey
from urtypes.crypto.hd_key import HDKey
from urtypes.crypto.multi_key import MultiKey
from urtypes.crypto.output import Output, ScriptExpression
from urtypes.crypto.psbt import PSBT


def generic_eq(self, other):
    """Generic equality comparison for test assertions."""
    if not isinstance(other, self.__class__):
        return False
    return all(
        getattr(self, attr) == getattr(other, attr)
        for attr in self.__dict__
    )


@pytest.fixture(scope="session", autouse=True)
def inject_test_equality():
    """
    Automatically inject __eq__() into all registry classes for testing.
    
    This approach keeps production code clean (no __eq__ boilerplate)
    while enabling test assertions like assertEqual() to work correctly.
    
    The fixture is automatically used (autouse=True) and runs once per session.
    """
    # Inject equality into all classes used in tests
    classes_to_patch = [
        # Core classes
        Bytes,
        # CBOR classes
        DataItem,
        Tagging,
        # Crypto classes
        BIP39,
        CoinInfo,
        Keypath,
        PathComponent,
        Account,
        ECKey,
        HDKey,
        MultiKey,
        Output,
        ScriptExpression,
        PSBT,
    ]
    
    for cls in classes_to_patch:
        # Always inject to ensure all classes have __eq__ for testing
        cls.__eq__ = generic_eq
    
    yield  # Fixture runs before tests
