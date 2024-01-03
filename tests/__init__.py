import binascii

from pyasn1_fasder import decode_der


def _wrapper(substrate_hex, asn1Spec):
    return decode_der(binascii.unhexlify(substrate_hex), asn1Spec=asn1Spec)


MAX = float('inf')
