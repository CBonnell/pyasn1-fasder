import binascii

import pytest
from pyasn1.error import PyAsn1Error

from pyasn1.type import univ, char, namedval

from pyasn1_fasder import decode_der


def _wrapper(substrate_hex, asn1Spec):
    return decode_der(binascii.unhexlify(substrate_hex), asn1Spec=asn1Spec)


def test_boolean_true():
    decoded, _ = _wrapper(b'0101FF', univ.Boolean())
    assert bool(decoded)


def test_boolean_false():
    decoded, _ = _wrapper(b'010100', univ.Boolean())
    assert not bool(decoded)


def test_boolean_bad_length():
    with pytest.raises(PyAsn1Error):
        decoded, _ = _wrapper(b'01020000', univ.Boolean())


def test_boolean_bad_true_value():
    with pytest.raises(PyAsn1Error):
        decoded, _ = _wrapper(b'010101', univ.Boolean())


def test_integer_positive():
    decoded, _ = _wrapper(b'020101', univ.Integer())

    assert int(decoded) == 1


def test_integer_negative():
    decoded, _ = _wrapper(b'0201FF', univ.Integer())

    assert int(decoded) == -1


def test_integer_zero_extra_octet():
    with pytest.raises(PyAsn1Error):
        decoded, _ = _wrapper(b'02020000', univ.Integer())


def test_integer_one_leading_zero():
    with pytest.raises(PyAsn1Error):
        decoded, _ = _wrapper(b'0202007F', univ.Integer())


def test_integer_negative_one_leading_all_one_bits():
    with pytest.raises(PyAsn1Error):
        decoded, _ = _wrapper(b'0202FFFF', univ.Integer())


def test_bitstring_no_trailer_bit_count():
    with pytest.raises(PyAsn1Error):
        decoded, _ = _wrapper(b'0300', univ.BitString())


def test_bitstring_nonzero_trailer_bit_count_no_value_octets():
    with pytest.raises(PyAsn1Error):
        decoded, _ = _wrapper(b'030101', univ.BitString())


def test_bitstring_trailer_bit_count_overflow():
    with pytest.raises(PyAsn1Error):
        decoded, _ = _wrapper(b'03020800', univ.BitString())


def test_bitstring_one_value_no_trailer():
    decoded, _ = _wrapper(b'03020001', univ.BitString())

    assert decoded.asOctets() == b'\x01'


def test_bitstring_one_value_with_trailer():
    decoded, _ = _wrapper(b'03020102', univ.BitString())

    assert decoded.asOctets() == b'\x01'


class NamedBitString(univ.BitString):
    pass


NamedBitString.namedValues = namedval.NamedValues(
    ('foo', 0),
    ('bar', 1),
    ('baz', 2),
)


def test_named_bitstring_non_minimal_encoding():
    with pytest.raises(PyAsn1Error):
        _wrapper(b'03020002', NamedBitString())


def test_null():
    decoded, _ = _wrapper(b'0500', univ.Null())

    assert str(decoded) == ''


def test_null_too_long():
    with pytest.raises(PyAsn1Error):
        decoded, _ = _wrapper(b'0501FF', univ.Null())


def test_printablestring():
    decoded, _ = _wrapper(b'1303414243', char.PrintableString())

    assert str(decoded) == 'ABC'


def test_printablestring_badchar():
    with pytest.raises(PyAsn1Error):
        decoded, _ = _wrapper(b'13017E', char.PrintableString())
