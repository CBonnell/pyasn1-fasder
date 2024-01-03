from pyasn1.type import tag, tagmap

_TAG_CLS = tag.Tag
_TAGSET_CLS = tag.TagSet
_TAGMAP_CLS = tagmap.TagMap

_TAG_CACHE = {}
_TAGSET_CACHE = {}

_TYPE_MAP = {}

for tag_id in range(1, 30):
    tag_format = tag.tagFormatConstructed if tag_id in {16, 17} else tag.tagFormatSimple  # SEQUENCE and SET

    tag_octet = tag_format | tag_id

    tag_pyasn1 = tag.Tag(tag.tagClassUniversal, tag_format, tag_id)

    _TAG_CACHE[tag_octet] = tag_pyasn1

    tag_set = tag.TagSet((), tag_pyasn1)

    _TAGSET_CACHE[tag_pyasn1] = tag_set


_CONSTRUCTED_SET_COMPONENT_KWARGS = {
    "verifyConstraints": False,
    "matchTags": False,
    "matchConstraints": False,
}

_CHOICE_SET_COMPONENT_KWARGS = {
    **_CONSTRUCTED_SET_COMPONENT_KWARGS,
    "innerFlag": False,
}
