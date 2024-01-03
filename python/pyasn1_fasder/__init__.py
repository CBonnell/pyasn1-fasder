from typing import Tuple

from pyasn1.type.base import Asn1Type

from ._native import decode_der as native_decode_der


def decode_der(substrate, asn1Spec: Asn1Type) -> Tuple[Asn1Type, bytes]:
    """Decodes the specified substrate into an ASN.1 object with the specified schema object. Unlike the 'decode'
    functions in pyasn1, the schema object must be specified. Additionally, this function raises an exception if
    the substrate contains trailing octets. The second value of the tuple returned by this function is always an
    empty byte string.

    Parameters
    ----------

    substrate: object
        This argument must return a byte string if passed to the 'bytes' function.
    asn1Spec: object
        This argument specifies the ASN.1 schema to use for decoding the substrate.

    Raises
    ------
    PyAsn1Error
        If a decoding error occurs.
    """
    return native_decode_der(bytes(substrate), asn1Spec), b''
