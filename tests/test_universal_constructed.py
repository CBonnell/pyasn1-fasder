import pytest
from pyasn1 import error
from pyasn1.error import PyAsn1Error
from pyasn1.type import univ, namedtype, char, useful, constraint

from tests import _wrapper, MAX


class SequenceTest(univ.Sequence):
    pass


SequenceTest.componentType = namedtype.NamedTypes(
    namedtype.NamedType('first', char.PrintableString()),
    namedtype.OptionalNamedType('optional', char.UTF8String()),
    namedtype.DefaultedNamedType('default', useful.UTCTime().subtype(value='251231235959Z')),
    namedtype.NamedType('last', char.PrintableString()),
)


class SequenceOfTest(univ.SequenceOf):
    pass


SequenceOfTest.componentType = char.PrintableString()
SequenceOfTest.sizeSpec = constraint.ValueSizeConstraint(1, MAX)


class SetOfTest(univ.SetOf):
    pass


SetOfTest.componentType = char.PrintableString()
SetOfTest.sizeSpec = constraint.ValueSizeConstraint(1, MAX)



def test_sequenceof_one_element():
    decoded, _ = _wrapper(b'3003130141', SequenceOfTest())

    assert len(decoded) == 1
    assert str(decoded[0]) == 'A'


def test_sequenceof_two_elements():
    decoded, _ = _wrapper(b'3006130141130142', SequenceOfTest())

    assert len(decoded) == 2
    assert str(decoded[0]) == 'A'
    assert str(decoded[1]) == 'B'


def test_sequenceof_empty():
    with pytest.raises(error.PyAsn1Error):
        _wrapper(b'3000', SequenceOfTest())


def test_setof_one_element():
    decoded, _ = _wrapper(b'3103130141', SetOfTest())

    assert len(decoded) == 1
    assert str(decoded[0]) == 'A'


def test_setof_empty():
    with pytest.raises(error.PyAsn1Error):
        _wrapper(b'3100', SetOfTest())


def test_setof_two_elements():
    decoded, _ = _wrapper(b'3106130141130142', SetOfTest())

    assert len(decoded) == 2
    assert str(decoded[0]) == 'A'
    assert str(decoded[1]) == 'B'


def test_setof_two_elements_out_order():
    with pytest.raises(PyAsn1Error):
        decoded, _ = _wrapper(b'3106130142130141', SetOfTest())


def test_sequence_no_default_or_optional():
    decoded, _ = _wrapper(b'3006130141130142', SequenceTest())

    assert str(decoded['first']) == 'A'
    assert str(decoded['default']) == '251231235959Z'
    assert not decoded['optional'].isValue
    assert str(decoded['last']) == 'B'


def test_sequence_with_default_no_optional():
    decoded, _ = _wrapper(b'3015130141170D3234303130313030303030305A130142', SequenceTest())

    assert str(decoded['first']) == 'A'
    assert str(decoded['default']) == '240101000000Z'
    assert not decoded['optional'].isValue
    assert str(decoded['last']) == 'B'


def test_sequence_with_default_and_optional():
    decoded, _ = _wrapper(b'30181301410C0161170D3234303130313030303030305A130142', SequenceTest())

    assert str(decoded['first']) == 'A'
    assert str(decoded['optional']) == 'a'
    assert str(decoded['default']) == '240101000000Z'
    assert str(decoded['last']) == 'B'


def test_sequence_missing_element():
    with pytest.raises(PyAsn1Error):
        decoded, _ = _wrapper(b'30151301410C0161170D3234303130313030303030305A', SequenceTest())


def test_encoded_default_value():
    with pytest.raises(PyAsn1Error):
        decoded, _ = _wrapper(b'30181301410C0161170D3235313233313233353935395A130142', SequenceTest())
