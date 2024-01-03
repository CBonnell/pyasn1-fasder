import pytest
from pyasn1 import error
from pyasn1.type import univ, namedtype, char, tag
from . import MAX, _wrapper


class ImplicitSequence(univ.Sequence):
    pass


class ImplicitStrings(univ.SequenceOf):
    pass


ImplicitStrings.componentType = char.PrintableString()


ImplicitSequence.componentType = namedtype.NamedTypes(
    namedtype.NamedType('implicitString', char.PrintableString().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
    namedtype.NamedType('implicitSeq', ImplicitStrings().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)))
)


def test_decode_implicit():
    decoded, _ = _wrapper(b'300A8003414243A103130130', ImplicitSequence())

    assert str(decoded['implicitString']) == 'ABC'
    assert len(decoded['implicitSeq']) == 1
    assert str(decoded['implicitSeq'][0]) == '0'


class ExplicitSequence(univ.Sequence):
    pass


ExplicitSequence.componentType = namedtype.NamedTypes(
    namedtype.NamedType('explicit', char.PrintableString().subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)))
)


def test_decode_explicit():
    decoded, _ = _wrapper(b'3007A0051303414243', ExplicitSequence())

    assert str(decoded['explicit']) == 'ABC'


def test_invalid_nested_explicit_substrate():
    with pytest.raises(error.PyAsn1Error):
        decoded, _ = _wrapper(b'3007A005A003130130', ExplicitSequence())


def test_too_deep_nested_explicit_substrate():
    substrate = b'300D' + b'A00B' + b'A009' + b'A007' + b'A005' + b'A003' + b'130130'

    with pytest.raises(error.PyAsn1Error):
        decoded, _ = _wrapper(substrate, ExplicitSequence())
