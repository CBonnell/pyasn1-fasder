mod tag;
mod decoder;
mod asn1_type;

use std::clone::Clone;
use pyo3::prelude::*;
use pyo3::intern;
use pyo3::types::{PyAny, PyDict};
use crate::decoder::{decode_asn1_spec_value, DecodeStep};
use crate::tag::{Asn1Tag, CLASS_UNIVERSAL};


pyo3::import_exception!(pyasn1_fasder.error, Pyasn1FasderError);


const TAGSET_ATTR: &str = "tagSet";
const TAGMAP_ATTR: &str = "tagMap";
const TYPE_MAP: &str = "_TYPE_MAP";
const HELPER_MODULE_ATTR: &str = "_HELPER";

const NESTED_EXPLICIT_TAG_LIMIT: usize = 4;


#[derive(Clone)]
pub struct NativeHelperModule<'py> {
    module: Bound<'py, PyModule>,
    tag_cls: Bound<'py, PyAny>,
    tagset_cls: Bound<'py, PyAny>,
    tagmap_cls: Bound<'py, PyAny>,
    tag_cache: Bound<'py, PyDict>,
    tagset_cache: Bound<'py, PyDict>,
    decoder_mappings: Bound<'py, PyDict>,
}

impl<'py> NativeHelperModule<'py> {
    pub fn new(base_module: &Bound<'py, PyModule>) -> PyResult<Self> {
        let py = base_module.py();

        let module_attr = base_module.getattr(intern![py, HELPER_MODULE_ATTR])?;
        let module: Bound<PyModule> = module_attr.downcast_exact()?.clone();

        let tag_cls = module.getattr(intern![py, "_TAG_CLS"])?;
        let tagset_cls = module.getattr(intern![py, "_TAGSET_CLS"])?;
        let tagmap_cls = module.getattr(intern![py, "_TAGMAP_CLS"])?;

        let tag_cache_attr = module.getattr(intern![py, "_TAG_CACHE"])?;
        let tag_cache = tag_cache_attr.downcast_exact()?.clone();

        let tagset_cache_attr = module.getattr(intern![py, "_TAGSET_CACHE"])?;
        let tagset_cache = tagset_cache_attr.downcast_exact()?.clone();

        let decoder_mappings_attr = module.getattr(intern![py, TYPE_MAP])?;
        let decoder_mappings = decoder_mappings_attr.downcast_exact()?.clone();

        Ok(Self { module, tag_cls, tagset_cls, tagmap_cls, tag_cache, tagset_cache, decoder_mappings })
    }

    pub fn create_pyasn1_tag(&self, tag: Asn1Tag) -> PyResult<Bound<PyAny>> {
        if tag.class() == CLASS_UNIVERSAL {
            let cached_tag = self.tag_cache.get_item(u8::from(tag))?;

            if cached_tag.is_some() {
                return Ok(cached_tag.unwrap())
            }
        }

        self.tag_cls.call((tag.class(), tag.format(), tag.tag_id()), None)
    }

    pub fn create_pyasn1_tagset(&self, pyasn1_tag: &Bound<PyAny>, tag: Asn1Tag) -> PyResult<Bound<'py, PyAny>> {
        if tag.class() == CLASS_UNIVERSAL {
            let cached_tagset = self.tagset_cache.get_item(pyasn1_tag)?;

            if cached_tagset.is_some() {
                return Ok(cached_tagset.unwrap())
            }
        }

        self.tagset_cls.call(((), pyasn1_tag), None)
    }
}


fn decode_explicit<'call, 'py>(step: DecodeStep<'py>) -> PyResult<Bound<'py, PyAny>> where 'py: 'call {
    // stop recursion if we've already descended multiple times
    if step.tag_set().len()? >= NESTED_EXPLICIT_TAG_LIMIT {
        return Err(step.create_error("Exceeded limit on nested explicit tags"))
    }

    let first_tag = step.tag_set().get_item(0)?;
    let first_tag_fmt = first_tag.get_item(1)?;
    let first_tag_class = first_tag.get_item(0)?;

    if first_tag_fmt.eq(tag::FORMAT_CONSTRUCTED)? && first_tag_class.ne(CLASS_UNIVERSAL)? {
        let new_offset = step.offset() + usize::try_from(step.header().length).unwrap();

        decode_der_rec(step.module().clone(), step.value_substrate(), step.asn1_spec().clone(), Some(
            step.tag_set().clone()), new_offset)
    }
    else {
        Err(step.create_error("Substrate does not match ASN.1 specification"))
    }
}


pub fn get_chosen_spec<'py>(m: &NativeHelperModule, asn1_spec: &pyo3::Bound<'py, PyAny>, substrate_tag_set: &Bound<PyAny>) -> PyResult<Option<Bound<'py, PyAny>>> {
    let py = asn1_spec.py();

    if asn1_spec.get_type().is(&m.tagmap_cls) {
        match asn1_spec.get_item(substrate_tag_set) {
            Err(_) => Ok(None),
            Ok(c) => Ok(Some(c))
        }
    }
    else if substrate_tag_set.eq(asn1_spec.getattr(intern![py, TAGSET_ATTR])?)? || asn1_spec.getattr(intern![py, TAGMAP_ATTR])?.contains(substrate_tag_set)? {
        Ok(Some(asn1_spec.clone()))
    }
    else {
        Ok(None)
    }
}


fn decode_der_rec<'py>(m: NativeHelperModule<'py>, substrate: &'py [u8], asn1_spec: Bound<'py, PyAny>, tag_set: Option<Bound<'py, PyAny>>, offset: usize) -> PyResult<Bound<'py, PyAny>> {
    if asn1_spec.is_none() {
        return Err(Pyasn1FasderError::new_err(format!("No ASN.1 specification near substrate offset {}", offset)));
    }

    let (header, tlv_octets) = match decoder::read_tlv(substrate, offset) {
        Ok(header_and_octets) => header_and_octets,
        Err(e) => return Err(e)
    };

    if substrate.len() != tlv_octets.len() {
        return Err(Pyasn1FasderError::new_err(format!("{} trailing octet(s) after TLV near substrate offset {}", substrate.len() - tlv_octets.len(), offset)));
    }

    // initialize tag and tagSet from decoded substrate

    let substrate_tag = m.create_pyasn1_tag(Asn1Tag::new(substrate[0]))?;

    let new_tag_set = match tag_set {
        Some(pyasn1_tagset) => pyasn1_tagset.call_method(intern![m.module.py(), "__radd__"], (substrate_tag,), None)?,
        None => m.create_pyasn1_tagset(&substrate_tag, Asn1Tag::new(substrate[0]))?.to_owned()
    };

    // determine ASN.1 spec to use for value decoding

    let chosen_spec = match get_chosen_spec(&m, &asn1_spec, &new_tag_set) {
        Ok(None) => return decode_explicit(DecodeStep::new(m.clone(), substrate, header, asn1_spec.clone(), new_tag_set, offset)),
        Ok(Some(c)) => c,
        Err(e) => return Err(e),
    };

    // create a new step with the chosen ASN.1 spec

    let step = DecodeStep::new(m.clone(), substrate, header, chosen_spec, new_tag_set, offset);

    // find decoder for chosen ASN.1 spec and decode substrate value
    decode_asn1_spec_value(step)
}


#[pyfunction]
#[pyo3(pass_module)]
fn decode_der<'py>(m: &Bound<'py, PyModule>, substrate: &'py [u8], asn1_spec: &'py Bound<'py, PyAny>) -> PyResult<Bound<'py, PyAny>> {
    let native_module = NativeHelperModule::new(m)?;

    decode_der_rec(native_module, substrate, asn1_spec.clone(), None, 0)
}


fn initialize_module(m: &Bound<PyModule>) -> PyResult<()> {
    let helper_mod = m.py().import_bound("pyasn1_fasder._native_helper")?;

    m.setattr(HELPER_MODULE_ATTR, helper_mod)?;

    tag::init_module(m)?;

    decoder::init_module(m)
}


#[pymodule]
#[pyo3(name="_native")]
fn pyasn1_fasder(_py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(decode_der, m)?)?;

    initialize_module(m)?;

    Ok(())
}
