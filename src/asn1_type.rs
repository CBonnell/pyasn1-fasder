use pyo3::{intern, IntoPy, PyAny, PyErr, PyObject, PyResult};
use pyo3::types::{IntoPyDict, PyBytes, PyDict, PySet, PyTuple};
use der::asn1::{ObjectIdentifier, PrintableStringRef};
use itertools::Itertools;
use crate::{decode_der_rec, decode_explicit, decoder, get_chosen_spec, NativeHelperModule, tag, TAGSET_ATTR};
use crate::decoder::DecodeStep;


const CONSTRUCTED_SET_COMPONENT_KWARGS: &str = "_CONSTRUCTED_SET_COMPONENT_KWARGS";
const CHOICE_SET_COMPONENT_KWARGS: &str = "_CHOICE_SET_COMPONENT_KWARGS";



fn create_value_args(value: &PyAny) -> &PyTuple {
    PyTuple::new(value.py(), vec![value])
}


fn clone_asn1_schema_obj<'py>(asn1_schema_obj: &'py PyAny, args: &PyTuple, kwargs: Option<&PyDict>) -> PyResult<&'py PyAny> {
    asn1_schema_obj.call_method(intern![asn1_schema_obj.py(), "clone"], args, kwargs)
}

pub trait Decoder<'py> {
    fn verify_raw(self: &Self) -> PyResult<()> {
        Ok(())
    }

    fn decode(self: &Self) -> PyResult<&'py PyAny>;

    fn verify_decoded(self: &Self, _asn1_value: &PyAny) -> PyResult<()> {
        Ok(())
    }
}


pub struct BooleanDecoder<'py> {
    step: DecodeStep<'py>
}

impl<'py> BooleanDecoder<'py> {
    pub fn new(step: DecodeStep<'py>) -> Self {
        Self { step }
    }
}

impl<'py> Decoder<'py> for BooleanDecoder<'py> {
    fn verify_raw(&self) -> PyResult<()> {
        if self.step.tag().format() != tag::FORMAT_SIMPLE {
            return Err(self.step.create_error("Invalid BOOLEAN value format"));
        }

        match self.step.value_substrate_len() {
            1 => {
                if self.step.value_substrate()[0] != 0 && self.step.value_substrate()[0] != 0xFF {
                    Err(self.step.create_error("Non-canonical BOOLEAN encoding"))
                }
                else {
                    Ok(())
                }
            }
            l => Err(self.step.create_error(&format!("Invalid BOOLEAN value length of {} octets", l)))
        }
    }

    fn decode(&self) -> PyResult<&'py PyAny> {
        let py = self.step.asn1_spec().py();

        let mapped_int_bool: u8 = match self.step.value_substrate()[0] {
            0 => 0,
            _ => 1,
        };

        let py_value: PyObject = mapped_int_bool.into_py(py);

        clone_asn1_schema_obj(self.step.asn1_spec(), create_value_args(py_value.as_ref(py)), None)
    }
}


pub struct IntegerDecoder<'py> {
    step: DecodeStep<'py>,
    type_name: &'static str
}

impl<'py> IntegerDecoder<'py> {
    pub(crate) fn new(step: DecodeStep<'py>, type_name: &'static str) -> Self {
        Self { step, type_name }
    }
}

impl<'py> Decoder<'py> for IntegerDecoder<'py> {
    fn verify_raw(self: &Self) -> PyResult<()> {
        if self.step.tag().format() != tag::FORMAT_SIMPLE {
            return Err(self.step.create_error(&format!("Invalid {} value format", self.type_name)));
        }

        let value_substrate = self.step.value_substrate();

        if value_substrate.len() == 0 {
            return Err(self.step.create_error(&format!("Substrate under-run in {} value", self.type_name)))
        }
        else if value_substrate.len() >= 2 {
            if (value_substrate[0] == 0 && value_substrate[1] & 0x80 == 0) || (value_substrate[0] == 0xFF && value_substrate[1] & 0x80 != 0) {
                return Err(self.step.create_error(&format!("Non-minimal {} encoding", self.type_name)))
            }
        }

        Ok(())
    }

    fn decode(self: &Self) -> PyResult<&'py PyAny> {
        let py = self.step.asn1_spec().py();

        let py_value = num_bigint::BigInt::from_signed_bytes_be(self.step.value_substrate()).into_py(py).into_ref(py);

        clone_asn1_schema_obj(self.step.asn1_spec(), create_value_args(py_value), None)
    }
}

pub struct BitStringDecoder<'py> {
    step: DecodeStep<'py>
}

impl<'py> BitStringDecoder<'py> {
    pub(crate) fn new(step: DecodeStep<'py>) -> Self {
        Self { step }
    }

    fn check_named_bit_string(self: &Self, trailer_bit_count: u8, last_octet: u8) -> PyResult<()> {
        let last_value_bit_mask = 1 << trailer_bit_count;

        if last_value_bit_mask & last_octet == 0 {
            Err(self.step.create_error("Trailing zero bit in named BIT STRING"))
        }
        else {
            Ok(())
        }
    }
}

impl<'py> Decoder<'py> for BitStringDecoder<'py> {
    fn verify_raw(self: &Self) -> PyResult<()> {
        if self.step.tag().format() != tag::FORMAT_SIMPLE {
            return Err(self.step.create_error("Invalid BIT STRING value format"));
        }

        let value_substrate = self.step.value_substrate();

        let value_substrate_len = value_substrate.len();

        if value_substrate_len == 0 {
            return Err(self.step.create_error("Substrate under-run in BIT STRING"));
        }

        let trailer_bit_count = value_substrate[0];

        if trailer_bit_count > 7 || (value_substrate_len == 1 && trailer_bit_count != 0) {
            return Err(self.step.create_error(&format!("Invalid trailer length of {} bits in BIT STRING", trailer_bit_count)));
        }

        if value_substrate_len >= 2 {
            let trailer_bits = value_substrate[value_substrate_len - 1] & ((1 << trailer_bit_count) - 1);

            if trailer_bits != 0 {
                return Err(self.step.create_error("Non-zero trailer value in BIT STRING"));
            }

            if self.step.asn1_spec().getattr(intern![self.step.asn1_spec().py(), "namedValues"]).unwrap().is_true().unwrap() {
                let last_octet = value_substrate[value_substrate_len - 1];

                return self.check_named_bit_string(trailer_bit_count, last_octet)
            }
        }

        Ok(())
    }

    fn decode(self: &Self) -> PyResult<&'py PyAny> {
        let py = self.step.asn1_spec().py();

        let value = self.step.asn1_spec().call_method(
            intern![py, "fromOctetString"], create_value_args(PyBytes::new(py, &self.step.value_substrate()[1..])),
            Some([
                (intern![py, "internalFormat"], true.into_py(py).as_ref(py)),
                (intern![py, "padding"], self.step.value_substrate()[0].into_py(py).as_ref(py))]
                .into_py_dict(py))
        )?;

        clone_asn1_schema_obj(self.step.asn1_spec(), create_value_args(value), None)
    }
}


pub struct OctetStringDecoder<'py> {
    step: DecodeStep<'py>
}

impl<'py> OctetStringDecoder<'py> {
    pub(crate) fn new(step: DecodeStep<'py>) -> Self {
        Self { step }
    }

}

impl<'py> Decoder<'py> for OctetStringDecoder<'py> {

    fn verify_raw(self: &Self) -> PyResult<()> {
        match self.step.tag().format() {
            tag::FORMAT_SIMPLE => Ok(()),
            _ => Err(self.step.create_error("Invalid OCTET STRING value format"))
        }
    }

    fn decode(self: &Self) -> PyResult<&'py PyAny> {
        let py = self.step.asn1_spec().py();

        clone_asn1_schema_obj(self.step.asn1_spec(), create_value_args(PyBytes::new(py, self.step.value_substrate())), None)
    }
}


pub struct NullDecoder<'py> {
    step: DecodeStep<'py>
}

impl<'py> NullDecoder<'py> {
    pub(crate) fn new(step: DecodeStep<'py>) -> Self {
        Self { step }
    }
}

impl<'py> Decoder<'py> for NullDecoder<'py> {
    fn verify_raw(self: &Self) -> PyResult<()> {
        if self.step.tag().format() != tag::FORMAT_SIMPLE {
            return Err(self.step.create_error("Invalid NULL value format"))
        }

        match self.step.value_substrate_len() {
            0 => Ok(()),
            _ => Err(self.step.create_error("Invalid NULL value length"))
        }
    }

    fn decode(self: &Self) -> PyResult<&'py PyAny> {
        let py = self.step.asn1_spec().py();

        clone_asn1_schema_obj(self.step.asn1_spec(), create_value_args(intern![py, ""]), None)
    }
}


pub struct ObjectIdentifierDecoder<'py> {
    step: DecodeStep<'py>
}

impl<'py> ObjectIdentifierDecoder<'py> {
    pub(crate) fn new(step: DecodeStep<'py>) -> Self {
        Self { step }
    }
}

impl<'py> Decoder<'py> for ObjectIdentifierDecoder<'py> {
    fn verify_raw(self: &Self) -> PyResult<()> {
        match self.step.tag().format() {
            tag::FORMAT_SIMPLE => Ok(()),
            _ => Err(self.step.create_error("Invalid OBJECT IDENTIFIER value format"))
        }
    }

    fn decode(self: &Self) -> PyResult<&'py PyAny> {
        let py = self.step.asn1_spec().py();

        match ObjectIdentifier::from_bytes(self.step.value_substrate()) {
            Ok(oid) => {
                clone_asn1_schema_obj(
                    self.step.asn1_spec(),
                    create_value_args(PyTuple::new(py, oid.arcs().collect_vec())),
                    None)
            }
            Err(e) => Err(self.step.create_error(&e.to_string()))
        }
    }
}


pub struct CharacterStringDecoder<'py> {
    step: DecodeStep<'py>,
    type_name: &'static str
}

impl<'py> CharacterStringDecoder<'py> {
    pub(crate) fn new(step: DecodeStep<'py>, type_name: &'static str) -> Self {
        Self { step, type_name }
    }
}

impl<'py> Decoder<'py> for CharacterStringDecoder<'py> {
    fn verify_raw(self: &Self) -> PyResult<()> {
        match self.step.tag().format() {
            tag::FORMAT_SIMPLE => Ok(()),
            _ => Err(self.step.create_error(&format!("Invalid {} value format", self.type_name)))
        }
    }

    fn decode(self: &Self) -> PyResult<&'py PyAny> {
        let py = self.step.asn1_spec().py();

        clone_asn1_schema_obj(self.step.asn1_spec(), create_value_args(PyBytes::new(py, self.step.value_substrate())), None)
    }
}

pub struct PrintableStringDecoder<'py> {
    step: DecodeStep<'py>
}

impl<'py> PrintableStringDecoder<'py> {
    pub(crate) fn new(step: DecodeStep<'py>) -> Self {
        Self { step }
    }
}

impl<'py> Decoder<'py> for PrintableStringDecoder<'py> {
    fn verify_raw(self: &Self) -> PyResult<()> {
        match self.step.tag().format() {
            tag::FORMAT_SIMPLE => (),
            _ => return Err(self.step.create_error("Invalid PRINTABLESTRING value format"))
        };

        match PrintableStringRef::new(self.step.value_substrate()) {
            Ok(_) => Ok(()),
            Err(e) => Err(self.step.create_error(&format!("Error decoding PRINTABLESTRING: {}", e.to_string())))
        }
    }

    fn decode(self: &Self) -> PyResult<&'py PyAny> {
        let py = self.step.asn1_spec().py();

        clone_asn1_schema_obj(self.step.asn1_spec(), create_value_args(PyBytes::new(py, self.step.value_substrate())), None)
    }
}


fn check_consistency(step: DecodeStep, asn1_value: &PyAny) -> PyResult<()> {
    let py = asn1_value.py();

    match asn1_value.getattr(intern![py, "isInconsistent"]) {
        Ok(o) => {
            if o.is_true().unwrap() {
                Err(step.create_error(&o.to_string()))
            }
            else {
                Ok(())
            }
        },
        Err(e) => Err(e)
    }

}


fn get_constructed_set_component_kwargs(m: NativeHelperModule) -> &PyDict {
    m.module.getattr(intern![m.module.py(), CONSTRUCTED_SET_COMPONENT_KWARGS]).unwrap().downcast_exact().unwrap()
}


fn get_choice_set_component_kwargs(m: NativeHelperModule) -> &PyDict {
    m.module.getattr(intern![m.module.py(), CHOICE_SET_COMPONENT_KWARGS]).unwrap().downcast_exact().unwrap()
}


pub struct SequenceDecoder<'py> {
    step: DecodeStep<'py>
}

impl<'py> SequenceDecoder<'py> {
    pub(crate) fn new(step: DecodeStep<'py>) -> Self {
        Self { step }
    }

    fn get_named_type_at_index(self: &Self, named_types: &'py PyAny, index: usize) -> PyResult<&'py PyAny> {
        match named_types.get_item(index) {
            Ok(n) => Ok(n),
            Err(_) => return Err(self.step.create_error("Excessive components detected"))
        }
    }

    fn get_component_type_for_index(self: &Self, named_types: &'py PyAny, named_type: &'py PyAny, is_optional_or_defaulted: bool, index: usize) -> PyResult<&'py PyAny> {
        let py = named_types.py();

        if is_optional_or_defaulted {
            named_types.call_method(intern![py, "getTagMapNearPosition"], (index,), None)
        }
        else {
            named_type.getattr(intern![py, "asn1Object"])
        }
    }

    fn check_decoded_for_default_value(self: &Self, named_type: &'py PyAny, decoded: &'py PyAny) -> Option<PyErr> {
        let py = named_type.py();

        if named_type.getattr(intern![py, "isDefaulted"]).unwrap().is_true().unwrap() {
            if decoded.eq(named_type.getattr(intern![py, "asn1Object"]).unwrap()).unwrap() {
                return Some(self.step.create_error("Explicitly encoded default value"))
            }
        }

        None
    }
}


impl<'py> Decoder<'py> for SequenceDecoder<'py> {
    fn verify_raw(self: &Self) -> PyResult<()> {
        match self.step.tag().format() {
            tag::FORMAT_CONSTRUCTED => Ok(()),
            _ => return Err(self.step.create_error("Invalid SEQUENCE value format"))
        }
    }

    fn decode(self: &Self) -> PyResult<&'py PyAny> {
        let py = self.step.asn1_spec().py();

        let asn1_object = self.step.asn1_spec().call_method(intern![py, "clone"], PyTuple::empty(py), None).unwrap();
        asn1_object.call_method(intern![py, "clear"], PyTuple::empty(py), None)?;

        let named_types = self.step.asn1_spec().getattr(intern![py, "componentType"])?;

        let mut index = 0;
        let mut relative_offset = 0;
        let seen_indices = PySet::empty(py)?;

        while relative_offset < self.step.value_substrate_len() {
            let offset_from_parent_tlv = self.step.offset() + self.step.header_len() + relative_offset;

            let named_type = match self.get_named_type_at_index(named_types, index) {
                Ok(n) => n,
                Err(e) => return Err(e)
            };

            let is_optional_or_defaulted = named_type.getattr(intern![py, "isOptional"]).unwrap().is_true().unwrap() || named_type.getattr(intern![py, "isDefaulted"]).unwrap().is_true().unwrap();

            let component_type = match self.get_component_type_for_index(named_types, named_type, is_optional_or_defaulted, index) {
                Ok(c) => c,
                Err(e) => return Err(e)
            };

            let (_, tlv) = match decoder::read_tlv(&self.step.value_substrate()[relative_offset..], offset_from_parent_tlv) {
                Ok(header_and_tlv) => header_and_tlv,
                Err(e) => return Err(e)
            };

            let decoded = match decode_der_rec(self.step.module(), tlv, component_type, None, offset_from_parent_tlv) {
                Ok(d) => d,
                Err(e) => return Err(e)
            };

            match self.check_decoded_for_default_value(named_type, decoded) {
                Some(e) => return Err(e),
                None => ()
            };

            if is_optional_or_defaulted {
                index = named_types.call_method(intern![py, "getPositionNearType"], (decoded.getattr(intern![py, "effectiveTagSet"]).unwrap(), index.into_py(py)), None).unwrap().extract().unwrap();
            }

            asn1_object.call_method(intern![py, "setComponentByPosition"], (index, decoded), Some(get_constructed_set_component_kwargs(self.step.module()))).unwrap();

            seen_indices.add(index).unwrap();

            index += 1;
            relative_offset += tlv.len();
        }

        let required_components = named_types.getattr(intern![py, "requiredComponents"]).unwrap();

        if required_components.call_method(intern![py, "issubset"], (seen_indices,), None).unwrap().is_true().unwrap() {
            Ok(asn1_object)
        } else {
            Err(self.step.create_error("Missing required components"))
        }
    }

    fn verify_decoded(self: &Self, asn1_value: &PyAny) -> PyResult<()> {
        check_consistency(self.step, asn1_value)
    }
}

pub struct SequenceOfDecoder<'py> {
    step: DecodeStep<'py>
}

impl<'py> SequenceOfDecoder<'py> {
    pub(crate) fn new(step: DecodeStep<'py>) -> Self {
        Self { step }
    }
}

impl<'py> Decoder<'py> for SequenceOfDecoder<'py> {
    fn verify_raw(self: &Self) -> PyResult<()> {
        match self.step.tag().format() {
            tag::FORMAT_CONSTRUCTED => Ok(()),
            _ => return Err(self.step.create_error("Invalid SEQUENCE value format"))
        }
    }

    fn decode(self: &Self) -> PyResult<&'py PyAny> {
        let py = self.step.asn1_spec().py();

        let asn1_object = self.step.asn1_spec().call_method(intern![py, "clone"], PyTuple::empty(py), None).unwrap();
        asn1_object.call_method(intern![py, "clear"], PyTuple::empty(py), None)?;

        let mut index = 0;
        let mut relative_offset = 0;

        let component_type = self.step.asn1_spec().getattr(intern![py, "componentType"]).unwrap();

        while relative_offset < self.step.value_substrate_len() {
            let offset_from_parent_tlv = self.step.offset() + self.step.header_len() + relative_offset;

            let (_, tlv) = match decoder::read_tlv(&self.step.value_substrate()[relative_offset..], offset_from_parent_tlv) {
                Ok(header_and_tlv) => header_and_tlv,
                Err(e) => return Err(e)
            };

            let decoded = match decode_der_rec(self.step.module(), tlv, component_type, None, offset_from_parent_tlv) {
                Ok(d) => d,
                Err(e) => return Err(e)
            };

            asn1_object.call_method(intern![py, "setComponentByPosition"], (index, decoded), Some(get_constructed_set_component_kwargs(self.step.module()))).unwrap();

            index += 1;
            relative_offset += tlv.len();
        }

        Ok(asn1_object)
    }

    fn verify_decoded(self: &Self, asn1_value: &PyAny) -> PyResult<()> {
        check_consistency(self.step, asn1_value)
    }
}


pub struct SetOfDecoder<'py> {
    step: DecodeStep<'py>
}

impl<'py> SetOfDecoder<'py> {
    pub(crate) fn new(step: DecodeStep<'py>) -> Self {
        Self { step }
    }
}


impl<'py> Decoder<'py> for SetOfDecoder<'py> {
    fn verify_raw(self: &Self) -> PyResult<()> {
        match self.step.tag().format() {
            tag::FORMAT_CONSTRUCTED => Ok(()),
            _ => return Err(self.step.create_error("Invalid SET value format"))
        }
    }

    fn decode(self: &Self) -> PyResult<&'py PyAny> {
        let py = self.step.asn1_spec().py();

        let asn1_object = self.step.asn1_spec().call_method(intern![py, "clone"], PyTuple::empty(py), None).unwrap();
        asn1_object.call_method(intern![py, "clear"], PyTuple::empty(py), None)?;

        let mut index = 0;
        let mut relative_offset = 0;
        let mut last_tlv = None;

        let component_type = self.step.asn1_spec().getattr(intern![py, "componentType"]).unwrap();

        while relative_offset < self.step.value_substrate_len() {
            let offset_from_parent_tlv = self.step.offset() + self.step.header_len() + relative_offset;

            let (_, tlv) = match decoder::read_tlv(&self.step.value_substrate()[relative_offset..], offset_from_parent_tlv) {
                Ok(header_and_tlv) => header_and_tlv,
                Err(e) => return Err(e)
            };

            match last_tlv {
                Some(l) => {
                    if l > tlv {
                        return Err(self.step.create_error(&format!("Out of order component at index {}", index)))
                    }

                    last_tlv = Some(tlv);
                }
                None => last_tlv = Some(tlv)
            };

            let decoded = match decode_der_rec(self.step.module(), tlv, component_type, None, offset_from_parent_tlv) {
                Ok(d) => d,
                Err(e) => return Err(e)
            };

            asn1_object.call_method(intern![py, "setComponentByPosition"], (index, decoded), Some(get_constructed_set_component_kwargs(self.step.module()))).unwrap();

            index += 1;
            relative_offset += tlv.len();
        }

        Ok(asn1_object)
    }

    fn verify_decoded(self: &Self, asn1_value: &PyAny) -> PyResult<()> {
        check_consistency(self.step, asn1_value)
    }
}

pub struct AnyDecoder<'py> {
    step: DecodeStep<'py>
}

impl<'py> AnyDecoder<'py> {
    pub(crate) fn new(step: DecodeStep<'py>) -> Self {
        Self { step }
    }
}

impl<'py> Decoder<'py> for AnyDecoder<'py> {
    fn decode(self: &Self) -> PyResult<&'py PyAny> {
        let py = self.step.asn1_spec().py();

        let is_untagged = if self.step.asn1_spec().get_type().is(self.step.module().tagmap_cls) {
            !self.step.asn1_spec().contains(self.step.tag_set()).unwrap()
        } else {
            self.step.tag_set().ne(self.step.asn1_spec().getattr(intern![py, TAGSET_ATTR]).unwrap()).unwrap()
        };

        let substrate = if is_untagged {
            self.step.substrate()
        }
        else {
            self.step.value_substrate()
        };

        clone_asn1_schema_obj(self.step.asn1_spec(), create_value_args(PyBytes::new(py, substrate)), None)
    }
}


pub struct ChoiceDecoder<'py> {
    step: DecodeStep<'py>
}

impl<'py> ChoiceDecoder<'py> {
    pub(crate) fn new(step: DecodeStep<'py>) -> Self {
        Self { step }
    }
}

impl<'py> Decoder<'py> for ChoiceDecoder<'py> {
    fn decode(self: &Self) -> PyResult<&'py PyAny> {
        let py = self.step.asn1_spec().py();

        let asn1_object = self.step.asn1_spec().call_method(intern![py, "clone"], (), None).unwrap();

        let component_tag_map = asn1_object.getattr(intern![py, "componentTagMap"]).unwrap();

        let decoded_result = if asn1_object.getattr(intern![py, TAGSET_ATTR]).unwrap().eq(self.step.tag_set()).unwrap() {
            decode_der_rec(self.step.module(), self.step.value_substrate(), component_tag_map, None, self.step.header_len() + self.step.offset())
        }
        else {
            let chosen_spec = match get_chosen_spec(self.step.module(), component_tag_map, self.step.tag_set()) {
                Err(e) => return Err(e),
                Ok(None) => return decode_explicit(self.step),
                Ok(Some(c)) => c
            };

            let new_step = DecodeStep::new(self.step.module(), self.step.substrate(), self.step.header(), chosen_spec, self.step.tag_set(), self.step.offset());

            decoder::decode_asn1_spec_value(new_step)
        };

        match decoded_result {
            Err(e) => Err(e),
            Ok(d) => {
                let effective_tag_set = d.getattr(intern![py, "effectiveTagSet"]).unwrap();

                asn1_object.call_method(intern![py, "setComponentByType"], (effective_tag_set, d), Some(get_choice_set_component_kwargs(self.step.module())))
            }
        }
    }
}
