"""Namespace-preserving XML helpers for OOXML (.xlsx / .docx) processing."""

from __future__ import annotations

import io
import re
import xml.etree.ElementTree as ET
from typing import Iterable

XML_SPACE_ATTR = "{http://www.w3.org/XML/1998/namespace}space"
XMLNS_DECL_RE = re.compile(rb'xmlns(?::([A-Za-z_][A-Za-z0-9._\-]*))?\s*=\s*"([^"]+)"')


def register_namespaces_from_bytes(xml_bytes: bytes) -> dict[str, str]:
    """Parse XML namespace declarations from raw XML bytes and register them with ET."""
    ns_map: dict[str, str] = {}
    for prefix_b, uri_b in XMLNS_DECL_RE.findall(xml_bytes[:8192]):
        prefix = prefix_b.decode("utf-8", errors="ignore")
        uri = uri_b.decode("utf-8", errors="ignore")
        if prefix not in ns_map:
            ns_map[prefix] = uri
            ET.register_namespace(prefix, uri)
    # Also run iterparse start-ns on full stream if needed for namespaces declared deeper.
    try:
        for _, (prefix, uri) in ET.iterparse(io.BytesIO(xml_bytes), events=("start-ns",)):
            if prefix not in ns_map:
                ns_map[prefix] = uri
                ET.register_namespace(prefix, uri)
    except ET.ParseError:
        pass
    return ns_map


def parse_xml(xml_bytes: bytes) -> ET.Element:
    register_namespaces_from_bytes(xml_bytes)
    return ET.fromstring(xml_bytes)


def serialize_xml(root: ET.Element, xml_bytes_hint: bytes | None = None) -> bytes:
    if xml_bytes_hint is not None:
        register_namespaces_from_bytes(xml_bytes_hint)
    buf = io.BytesIO()
    tree = ET.ElementTree(root)
    tree.write(buf, encoding="utf-8", xml_declaration=True)
    return buf.getvalue()


def local_name(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def ensure_xml_space(elem: ET.Element, text: str) -> None:
    if text and (text[0].isspace() or text[-1].isspace()):
        elem.set(XML_SPACE_ATTR, "preserve")
    elif XML_SPACE_ATTR in elem.attrib and not text:
        del elem.attrib[XML_SPACE_ATTR]


def iter_children_by_local(parent: ET.Element, name: str) -> Iterable[ET.Element]:
    for child in parent:
        if local_name(child.tag) == name:
            yield child
