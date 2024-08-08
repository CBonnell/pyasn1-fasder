# pyasn1-fasder


[![PyPI](https://img.shields.io/pypi/v/pyasn1-fasder)](https://pypi.org/project/pyasn1-fasder)
[![Python Versions](https://img.shields.io/pypi/pyversions/pyasn1-fasder)](https://pypi.org/project/pyasn1-fasder/)
[![Build status](https://github.com/cbonnell/pyasn1-fasder/actions/workflows/CI.yml/badge.svg)](https://github.com/cbonnell/pyasn1-fasder/actions/workflows/CI.yml)
[![GitHub license](https://img.shields.io/pypi/l/pyasn1-fasder)](https://raw.githubusercontent.com/cbonnell/pyasn1-fasder/main/LICENSE)

pyasn1-fasder is a DER decoder for pyasn1 with a focus on checking the correctness of encoding. This decoder is more pedantic than most other decoders in terms of flagging DER
encoding errors, and this behavior is unlikely to change.

## Installation

`pip install pyasn1-fasder`

## Usage

pyasn1-fasder exposes a single function: `decode_der`. The signature and return type are the same as the pyasn1 `decode` function, as it is intended to be a drop-in replacement of `pyasn1.codec.der.decoder.decode`.

```python
from pyasn1.type.char import PrintableString
from pyasn1_fasder import decode_der

substrate = b'\x13\x03\x41\x42\x43'

decoded, rest = decode_der(substrate, asn1Spec=PrintableString())

assert rest == b''
assert str(decoded) == 'ABC'
```

## Limitations

* There is no encoding counterpart.
* Trailing octets present after the `substrate` TLV are not tolerated and will result in an exception being raised. In other words, the `rest` component of the tuple return value will always be an empty `bytes` object.
* Schemaless decoding is not supported. In other words, a non-`None` `asn1Spec` must be passed to `decode_der`.
* `Set`s with `namedTypes` are not supported. These are (almost?) never used in cryptography standards, but support can be added if there are valid use cases.
* `openTypes` decoding is currently not supported. This can be added if there is interest.
* The pedantic checks for correctness of encoding cannot be disabled.

## Bugs?

Please create a Github issue.

## Contributing

Contributions for bug fixes and new features are welcome.
