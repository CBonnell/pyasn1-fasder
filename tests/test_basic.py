from pyasn1.type import univ
from pyasn1.error import PyAsn1Error

import pytest

from pyasn1_fasder import decode_der


def test_none_substrate():
    with pytest.raises(TypeError):
        decode_der(None, asn1Spec=univ.OctetString())


def test_none_asn1spec():
    with pytest.raises(PyAsn1Error):
        decode_der(b'', asn1Spec=None)


def test_base_case():
    octet_string = b'\x04\x03\x61\x62\x63'

    decoded, rest = decode_der(octet_string, asn1Spec=univ.OctetString())

    assert rest == b''

    assert decoded.hasValue() and bytes(decoded) == b'\x61\x62\x63'


def test_trailing_octets():
    octet_string = b'\x04\x01\x61\x62\x63'

    with pytest.raises(PyAsn1Error):
        decoded, _ = decode_der(octet_string, asn1Spec=univ.OctetString())


def test_long_tag():
    octet_string = b'\x1F\x01\x01'

    with pytest.raises(PyAsn1Error):
        decoded, _ = decode_der(octet_string, asn1Spec=univ.OctetString())


def test_tag_mismatch():
    octet_string = b'\x04\x01\x01'

    with pytest.raises(PyAsn1Error):
        decoded, _ = decode_der(octet_string, asn1Spec=univ.BitString())
