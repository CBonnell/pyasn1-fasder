use der::{Encode, Header, Reader};
use pyo3::PyAny;
use pyo3::PyErr;
use pyo3::PyResult;
use pyo3::prelude::{PyModule};
use pyo3::types::PyDict;
use crate::{HELPER_MODULE_ATTR, NativeHelperModule, Pyasn1FasderError, TYPE_MAP};
use crate::asn1_type::{AnyDecoder, BitStringDecoder, BooleanDecoder, CharacterStringDecoder, ChoiceDecoder, Decoder, IntegerDecoder, NullDecoder, ObjectIdentifierDecoder, OctetStringDecoder, PrintableStringDecoder, SequenceDecoder, SequenceOfDecoder, SetOfDecoder};
use crate::tag::Asn1Tag;


const TYPE_ID_ATTR: &str = "typeId";


#[derive(Copy, Clone)]
pub struct DecodeStep<'py> {
    module: NativeHelperModule<'py>,
    substrate: &'py [u8],
    header: Header,
    asn1_spec: &'py PyAny,
    tag_set: &'py PyAny,
    offset: usize
}

impl<'py> DecodeStep<'py> {
    pub fn new(module: NativeHelperModule<'py>, substrate: &'py [u8], header: Header, asn1_spec: &'py PyAny, tag_set: &'py PyAny, offset: usize) -> Self {
        Self { module, substrate, header, asn1_spec, tag_set, offset }
    }

    pub fn module(&self) -> NativeHelperModule<'py> {
        self.module
    }

    pub fn substrate(&self) -> &'py [u8] {
        self.substrate
    }

    pub fn header(&self) -> Header {
        self.header
    }

    pub fn header_len(&self) -> usize {
        usize::try_from(self.header.encoded_len().unwrap()).unwrap()
    }

    pub fn tag(&self) -> Asn1Tag {
        Asn1Tag::new(self.substrate[0])
    }

    pub fn asn1_spec(&self) -> &'py PyAny {
        self.asn1_spec
    }

    pub fn tag_set(&self) -> &'py PyAny {
        self.tag_set
    }

    pub fn value_substrate_len(&self) -> usize {
        usize::try_from(self.header.length).unwrap()
    }

    pub fn value_substrate(&self) -> &'py [u8] {
        &self.substrate[self.header_len()..]
    }

    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn create_error(&self, description: &str) -> PyErr {
        let asn1_spec_name = self.asn1_spec.get_type().name().unwrap();

        Pyasn1FasderError::new_err(format!("Error decoding \"{}\" TLV near substrate offset {}: {}", asn1_spec_name, self.offset, description))
    }
}


pub fn read_tlv(substrate: &[u8], offset: usize) -> PyResult<(Header, &[u8])> {
    let mut reader = der::SliceReader::new(substrate).unwrap();

    let header = match reader.peek_header() {
        Err(e) => return Err(Pyasn1FasderError::new_err(format!("Error reading TLV header near substrate offset {}: {}", offset, e.to_string()))),
        Ok(h) => h
    };

    let tlv_octets = match reader.tlv_bytes() {
        Err(e) => return Err(Pyasn1FasderError::new_err(format!("Error reading TLV near substrate offset {}: {}", offset, e.to_string()))),
        Ok(tlv) => tlv
    };

    Ok((header, tlv_octets))
}


const DECODER_TYPE_BOOLEAN: usize = 1;
const DECODER_TYPE_INTEGER: usize = 2;
const DECODER_TYPE_BITSTRING: usize = 3;
const DECODER_TYPE_OCTETSTRING: usize = 4;
const DECODER_TYPE_NULL: usize = 5;
const DECODER_TYPE_OBJECTIDENTIFIER: usize = 6;
const DECODER_TYPE_ENUMERATED: usize = 10;
const DECODER_TYPE_UTF8STRING: usize = 12;
const DECODER_TYPE_SEQUENCE: usize = 16;
const DECODER_TYPE_SEQUENCEOF: usize = 32;
const DECODER_TYPE_SETOF: usize = 17;
const DECODER_TYPE_NUMERICSTRING: usize = 18;
const DECODER_TYPE_PRINTABLESTRING: usize = 19;
const DECODER_TYPE_TELETEXSTRING: usize = 20;
const DECODER_TYPE_VIDEOTEXSTRING: usize = 21;
const DECODER_TYPE_IA5STRING: usize = 22;
const DECODER_TYPE_UTCTIME: usize = 23;
const DECODER_TYPE_GENERALIZEDTIME: usize = 24;
const DECODER_TYPE_GRAPHICSTRING: usize = 25;
const DECODER_TYPE_VISIBLESTRING: usize = 26;
const DECODER_TYPE_UNIVERSALSTRING: usize = 28;
const DECODER_TYPE_BMPSTRING: usize = 30;
const DECODER_TYPE_ANY: usize = 98;
const DECODER_TYPE_CHOICE: usize = 99;



pub fn decode_asn1_spec_value(step: DecodeStep) -> PyResult<&PyAny> {
    let type_id = step.asn1_spec().getattr(TYPE_ID_ATTR).unwrap();

    match step.module.decoder_mappings.get_item(type_id).unwrap() {
        None => {
            let type_id_u8 : u8 = type_id.extract()?;

            Err(step.create_error(&format!("ASN.1 specification with type ID of {} is not supported", type_id_u8)))
        },
        Some(decoder_id) => {
            let decoder_id_u8: usize = decoder_id.extract().unwrap();

            let decoder: &dyn Decoder = match decoder_id_u8 {
                DECODER_TYPE_BOOLEAN => &BooleanDecoder::new(step),
                DECODER_TYPE_INTEGER => &IntegerDecoder::new(step, "INTEGER"),
                DECODER_TYPE_BITSTRING => &BitStringDecoder::new(step),
                DECODER_TYPE_OCTETSTRING => &OctetStringDecoder::new(step),
                DECODER_TYPE_NULL => &NullDecoder::new(step),
                DECODER_TYPE_OBJECTIDENTIFIER => &ObjectIdentifierDecoder::new(step),
                DECODER_TYPE_ENUMERATED => &IntegerDecoder::new(step, "ENUMERATED"),
                DECODER_TYPE_UTF8STRING => &CharacterStringDecoder::new(step, "UTF8STRING"),
                DECODER_TYPE_SEQUENCE => &SequenceDecoder::new(step),
                DECODER_TYPE_SEQUENCEOF => &SequenceOfDecoder::new(step),
                DECODER_TYPE_SETOF => &SetOfDecoder::new(step),
                DECODER_TYPE_NUMERICSTRING => &CharacterStringDecoder::new(step, "NUMERICSTRING"),
                DECODER_TYPE_PRINTABLESTRING => &PrintableStringDecoder::new(step),
                DECODER_TYPE_TELETEXSTRING => &CharacterStringDecoder::new(step, "TELETEXSTRING"),
                DECODER_TYPE_VIDEOTEXSTRING => &CharacterStringDecoder::new(step, "VIDEOTEXSTRING"),
                DECODER_TYPE_IA5STRING => &CharacterStringDecoder::new(step, "IA5STRING"),
                DECODER_TYPE_UTCTIME => &CharacterStringDecoder::new(step, "UTCTIME"),
                DECODER_TYPE_GENERALIZEDTIME => &CharacterStringDecoder::new(step, "GENERALIZEDTIME"),
                DECODER_TYPE_GRAPHICSTRING => &CharacterStringDecoder::new(step, "GRAPHICSTRING"),
                DECODER_TYPE_VISIBLESTRING => &CharacterStringDecoder::new(step, "VISIBLESTRING"),
                DECODER_TYPE_UNIVERSALSTRING => &CharacterStringDecoder::new(step, "UNIVERSALSTRING"),
                DECODER_TYPE_BMPSTRING => &CharacterStringDecoder::new(step, "BMPSTRING"),
                DECODER_TYPE_ANY => &AnyDecoder::new(step),
                DECODER_TYPE_CHOICE => &ChoiceDecoder::new(step),
                _ => return Err(Pyasn1FasderError::new_err("ASN.1 type is unsuppported"))
            };

            match decoder.verify_raw() {
                Err(e) => return Err(e),
                Ok(()) => ()
            };

            let decoded_result = decoder.decode();

            match decoded_result {
                Err(e) => Err(e),
                Ok(decoded) => {
                    match decoder.verify_decoded(decoded) {
                        Err(e) => Err(e),
                        Ok(()) => Ok(decoded)
                    }
                }
            }
        }
    }
}


pub fn init_module<'py>(m: &'py PyModule) -> PyResult<()> {
    let py = m.py();

    let helper_mod = m.getattr(HELPER_MODULE_ATTR)?;
    let type_map : &PyDict = helper_mod.getattr(TYPE_MAP).unwrap().downcast_exact().unwrap();

    let add_map_entry = |type_mod: &'py PyModule, cls_name: &str, decoder_type: usize| {
        let type_id = type_mod.getattr(cls_name).unwrap().getattr(TYPE_ID_ATTR).unwrap();

        type_map.set_item(type_id, decoder_type).unwrap()
    };

    let univ_mod = py.import("pyasn1.type.univ").unwrap();

    add_map_entry(univ_mod, "Boolean", DECODER_TYPE_BOOLEAN);
    add_map_entry(univ_mod, "Integer", DECODER_TYPE_INTEGER);
    add_map_entry(univ_mod, "BitString", DECODER_TYPE_BITSTRING);
    add_map_entry(univ_mod, "OctetString", DECODER_TYPE_OCTETSTRING);
    add_map_entry(univ_mod, "Null", DECODER_TYPE_NULL);
    add_map_entry(univ_mod, "ObjectIdentifier", DECODER_TYPE_OBJECTIDENTIFIER);
    add_map_entry(univ_mod, "Enumerated", DECODER_TYPE_ENUMERATED);
    add_map_entry(univ_mod, "Sequence", DECODER_TYPE_SEQUENCE);
    add_map_entry(univ_mod, "SequenceOf", DECODER_TYPE_SEQUENCEOF);
    add_map_entry(univ_mod, "SetOf", DECODER_TYPE_SETOF);
    add_map_entry(univ_mod, "Any", DECODER_TYPE_ANY);
    add_map_entry(univ_mod, "Choice", DECODER_TYPE_CHOICE);

    let char_mod = py.import("pyasn1.type.char").unwrap();

    add_map_entry(char_mod, "NumericString", DECODER_TYPE_NUMERICSTRING);
    add_map_entry(char_mod, "PrintableString", DECODER_TYPE_PRINTABLESTRING);
    add_map_entry(char_mod, "TeletexString", DECODER_TYPE_TELETEXSTRING);
    add_map_entry(char_mod, "VideotexString", DECODER_TYPE_VIDEOTEXSTRING);
    add_map_entry(char_mod, "IA5String", DECODER_TYPE_IA5STRING);
    add_map_entry(char_mod, "GraphicString", DECODER_TYPE_GRAPHICSTRING);
    add_map_entry(char_mod, "VisibleString", DECODER_TYPE_VISIBLESTRING);
    add_map_entry(char_mod, "UniversalString", DECODER_TYPE_UNIVERSALSTRING);
    add_map_entry(char_mod, "BMPString", DECODER_TYPE_BMPSTRING);
    add_map_entry(char_mod, "UTF8String", DECODER_TYPE_UTF8STRING);

    let useful_mod = py.import("pyasn1.type.useful")?;

    add_map_entry(useful_mod, "UTCTime", DECODER_TYPE_UTCTIME);
    add_map_entry(useful_mod, "GeneralizedTime", DECODER_TYPE_GENERALIZEDTIME);

    Ok(())
}
