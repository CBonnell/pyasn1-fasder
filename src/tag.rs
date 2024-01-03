use pyo3::PyResult;
use pyo3::types::PyModule;

pub const CLASS_MASK: u8 = 0xC0;
pub const CLASS_UNIVERSAL: u8 = 0x00;

pub const FORMAT_MASK: u8 = 0x20;
pub const FORMAT_CONSTRUCTED: u8 = 0x20;
pub const FORMAT_SIMPLE: u8 = 0x00;

const TAG_ID_MASK: u8 = 0x1F;

const TAG_CLS: &str = "_TAG_CLS";
const TAGSET_CLS: &str = "_TAGSET_CLS";
const TAG_CACHE: &str = "_TAG_CACHE";
const TAGSET_CACHE: &str = "_TAGSET_CACHE";
pub const TAGMAP_CLS: &str = "_TAGMAP_CLS";


#[derive(Copy, Clone)]
pub struct Asn1Tag {
    raw: u8
}

impl Asn1Tag {
    pub fn new(raw: u8) -> Self {
        Self { raw }
    }

    pub fn tag_id(&self) -> u8 {
        self.raw & TAG_ID_MASK
    }

    pub fn class(&self) -> u8 {
        self.raw & CLASS_MASK
    }

    pub fn format(&self) -> u8 {
        self.raw & FORMAT_MASK
    }
}

impl From<Asn1Tag> for u8 {
    fn from(value: Asn1Tag) -> Self {
        value.raw
    }
}

impl From<u8> for Asn1Tag {
    fn from(value: u8) -> Self {
        Self::new(value)
    }
}

pub fn init_module(m: &PyModule) -> PyResult<()> {
    let py = m.py();

    let pyasn1_tag_mod = py.import("pyasn1.type.tag")?;

    m.add(TAG_CLS, pyasn1_tag_mod.getattr("Tag")?)?;
    m.add(TAGSET_CLS, pyasn1_tag_mod.getattr("TagSet")?)?;
    m.add(TAGMAP_CLS, py.import("pyasn1.type.tagmap")?.getattr("TagMap")?)?;

    let helper_mod = py.import("pyasn1_fasder._native_helper")?;

    m.add(TAG_CACHE, helper_mod.getattr(TAG_CACHE)?)?;
    m.add(TAGSET_CACHE, helper_mod.getattr(TAGSET_CACHE)?)
}
