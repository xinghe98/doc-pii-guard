"""Lossless OOXML (.docx) PII masking, restoration, inspection, and template editing."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Sequence

from .pii import DEFAULT_CATEGORIES, apply_replacements, classify_header, find_pii_spans
from .table_ops import detect_header_row
from .vault import PIIVault
from .xml_utils import ensure_xml_space, local_name, parse_xml, serialize_xml

W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"

DOCX_TEXT_PARTS_RE = re.compile(
    r"^word/(?:document|header\d*|footer\d*|footnotes|endnotes|comments)\.xml$"
)


def _collect_paragraph_segments(
    p_elem: ET.Element,
) -> tuple[str, list[tuple[ET.Element, int, int]]]:
    """Collect text and direct `<w:t>` byte offsets owned by `p_elem`.

    Does not descend into nested `<w:p>` (e.g. inside `<w:txbxContent>`).
    Preserves `<w:tab/>` and `<w:br/>` as virtual whitespace separators.
    """
    pieces: list[str] = []
    t_entries: list[tuple[ET.Element, int, int]] = []
    offset = 0

    def walk(node: ET.Element) -> None:
        nonlocal offset
        for child in node:
            ln = local_name(child.tag)
            if ln == "p":
                continue  # Nested paragraph handled separately.
            if ln == "t":
                txt = child.text or ""
                start = offset
                end = start + len(txt)
                pieces.append(txt)
                t_entries.append((child, start, end))
                offset = end
            elif ln == "tab":
                pieces.append("\t")
                offset += 1
            elif ln in ("br", "cr"):
                pieces.append("\n")
                offset += 1
            else:
                walk(child)

    walk(p_elem)
    return "".join(pieces), t_entries


def _apply_replacements_to_t_entries(
    full_text: str,
    t_entries: list[tuple[ET.Element, int, int]],
    replacements: Sequence[tuple[int, int, str]],
) -> None:
    """Project character-span replacements back onto `<w:t>` XML elements."""
    if not replacements or not t_entries:
        return
    sorted_repls = sorted(replacements, key=lambda r: r[0])

    for t_elem, seg_start, seg_end in t_entries:
        if seg_start == seg_end:
            continue
        out_parts: list[str] = []
        cur = seg_start
        changed = False
        for s, e, tok in sorted_repls:
            if e <= seg_start:
                continue
            if s >= seg_end:
                break
            changed = True
            if s > cur:
                out_parts.append(full_text[cur:s])
            if seg_start <= s < seg_end:
                out_parts.append(tok)
            cur = min(seg_end, max(cur, e))
        if changed:
            if cur < seg_end:
                out_parts.append(full_text[cur:seg_end])
            new_seg = "".join(out_parts)
            t_elem.text = new_seg
            ensure_xml_space(t_elem, new_seg)


def _table_cell_text(tc_elem: ET.Element) -> str:
    paras: list[str] = []
    for node in tc_elem:
        if local_name(node.tag) == "p":
            txt, _ = _collect_paragraph_segments(node)
            paras.append(txt)
    return "\n".join(p for p in paras if p.strip()).strip()


def _detect_table_paragraph_categories(root: ET.Element) -> dict[int, str]:
    """Map id(p_elem) -> column_category for paragraphs inside PII table cells."""
    p_cats: dict[int, str] = {}

    for tbl in root.iter():
        if local_name(tbl.tag) != "tbl":
            continue
        rows_tc: list[list[ET.Element]] = []
        grid_text: list[list[str]] = []
        for tr in tbl:
            if local_name(tr.tag) != "tr":
                continue
            tcs = [ch for ch in tr if local_name(ch.tag) == "tc"]
            if not tcs:
                continue
            rows_tc.append(tcs)
            grid_text.append([_table_cell_text(tc) for tc in tcs])

        if not grid_text:
            continue

        # 1. Vertical table header classification.
        hdr_idx, col_cats = detect_header_row(grid_text)
        for r_idx in range(hdr_idx + 1, len(rows_tc)):
            for c_idx, tc in enumerate(rows_tc[r_idx]):
                cat = col_cats.get(c_idx)
                if cat:
                    # Skip repeated header text.
                    hdr_val = grid_text[hdr_idx][c_idx].strip() if c_idx < len(grid_text[hdr_idx]) else ""
                    if grid_text[r_idx][c_idx].strip() == hdr_val:
                        continue
                    for ch in tc:
                        if local_name(ch.tag) == "p":
                            p_cats[id(ch)] = cat

        # 2. Horizontal Key-Value pairs (e.g. | 姓名 | 张三 | 电话 | 138... |).
        for r_idx, row_vals in enumerate(grid_text):
            for c_idx in range(len(row_vals) - 1):
                key_txt = re.sub(r"[：:\s]+$", "", row_vals[c_idx].strip())
                cat = classify_header(key_txt)
                if cat:
                    next_txt = re.sub(r"[：:\s]+$", "", row_vals[c_idx + 1].strip())
                    if classify_header(next_txt) is None:
                        for ch in rows_tc[r_idx][c_idx + 1]:
                            if local_name(ch.tag) == "p":
                                p_cats[id(ch)] = cat
    return p_cats


def convert_doc_to_docx(doc_path: Path, out_docx_path: Path) -> None:
    """Convert legacy .doc to .docx using macOS `textutil` or LibreOffice."""
    textutil = shutil.which("textutil")
    if textutil:
        res = subprocess.run(
            [textutil, "-convert", "docx", "-output", str(out_docx_path), str(doc_path)],
            capture_output=True,
            text=True,
        )
        if res.returncode == 0 and out_docx_path.exists():
            return
        raise RuntimeError(f"textutil failed to convert .doc: {res.stderr.strip()}")
    soffice = shutil.which("soffice") or shutil.which("libreoffice")
    if soffice:
        res = subprocess.run(
            [soffice, "--headless", "--convert-to", "docx", "--outdir", str(out_docx_path.parent), str(doc_path)],
            capture_output=True,
            text=True,
        )
        converted = out_docx_path.parent / (doc_path.stem + ".docx")
        if res.returncode == 0 and converted.exists():
            if converted != out_docx_path:
                os.replace(converted, out_docx_path)
            return
        raise RuntimeError(f"LibreOffice failed to convert .doc: {res.stderr.strip()}")
    raise RuntimeError("Legacy .doc conversion requires macOS 'textutil' or LibreOffice 'soffice'.")


def mask_docx_file(
    source_path: Path,
    masked_path: Path,
    vault: PIIVault,
    *,
    extra_names: Sequence[str] = (),
    exclude_words: Sequence[str] = (),
    categories: Sequence[str] = DEFAULT_CATEGORIES,
) -> dict[str, Any]:
    masked_path.parent.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}

    def alloc(cat: str, canon: str, raw: str) -> str:
        tok = vault.get_or_create_token(cat, canon, raw)
        counts[cat] = counts.get(cat, 0) + 1
        return tok

    tmp_stage_dir = None
    actual_source = source_path
    if source_path.suffix.lower() == ".doc":
        tmp_stage_dir = tempfile.TemporaryDirectory(prefix="doc_pii_conv_")
        actual_source = Path(tmp_stage_dir.name) / f"{source_path.stem}.docx"
        convert_doc_to_docx(source_path, actual_source)

    try:
        with zipfile.ZipFile(actual_source, "r") as zin:
            parts: list[dict[str, Any]] = []
            for name in zin.namelist():
                if DOCX_TEXT_PARTS_RE.match(name):
                    raw = zin.read(name)
                    root = parse_xml(raw)
                    p_cats = _detect_table_paragraph_categories(root)
                    parts.append({"name": name, "raw": raw, "root": root, "p_cats": p_cats})

            # Pass 1: table cells + labeled patterns (discovers known_names).
            for part in parts:
                root = part["root"]
                p_cats = part["p_cats"]
                for elem in root.iter():
                    if local_name(elem.tag) != "p":
                        continue
                    text, t_entries = _collect_paragraph_segments(elem)
                    if not text.strip() or not t_entries:
                        continue
                    col_cat = p_cats.get(id(elem))
                    spans = find_pii_spans(
                        text,
                        column_category=col_cat,
                        known_names=vault.known_names,
                        extra_names=extra_names,
                        exclude_words=exclude_words,
                        categories=categories,
                    )
                    if spans:
                        _, repls = apply_replacements(text, spans, alloc)
                        _apply_replacements_to_t_entries(text, t_entries, repls)

            # Pass 2: cross-reference newly learned known_names in all paragraphs.
            modified: dict[str, bytes] = {}
            para_count = 0
            table_count = 0
            for part in parts:
                root = part["root"]
                for elem in root.iter():
                    ln = local_name(elem.tag)
                    if ln == "tbl" and part["name"] == "word/document.xml":
                        table_count += 1
                    if ln != "p":
                        continue
                    if part["name"] == "word/document.xml":
                        para_count += 1
                    text, t_entries = _collect_paragraph_segments(elem)
                    if not text.strip() or not t_entries:
                        continue
                    spans = find_pii_spans(
                        text,
                        column_category=None,
                        known_names=vault.known_names,
                        extra_names=extra_names,
                        exclude_words=exclude_words,
                        categories=categories,
                    )
                    if spans:
                        _, repls = apply_replacements(text, spans, alloc)
                        _apply_replacements_to_t_entries(text, t_entries, repls)
                modified[part["name"]] = serialize_xml(root, part["raw"])

            if "docProps/core.xml" in zin.namelist():
                core_raw = zin.read("docProps/core.xml")
                core_root = parse_xml(core_raw)
                changed = False
                for node in core_root.iter():
                    if local_name(node.tag) in ("creator", "lastModifiedBy") and node.text and node.text.strip():
                        node.text = "REDACTED"
                        changed = True
                if changed:
                    modified["docProps/core.xml"] = serialize_xml(core_root, core_raw)

            tmp_out = masked_path.with_suffix(masked_path.suffix + ".tmp")
            with zipfile.ZipFile(tmp_out, "w", compression=zipfile.ZIP_DEFLATED) as zout:
                for item in zin.infolist():
                    if item.filename in modified:
                        zout.writestr(item, modified[item.filename])
                    else:
                        zout.writestr(item, zin.read(item.filename))
            zin.close()  # Windows: release the source handle before replacing it
            os.replace(tmp_out, masked_path)
    finally:
        if tmp_stage_dir is not None:
            tmp_stage_dir.cleanup()

    return {
        "paragraphs": para_count,
        "tables": table_count,
        "pii_counts": counts,
    }


def restore_docx_file(
    masked_path: Path,
    output_path: Path,
    vault: PIIVault,
    *,
    irreversible_style: str | None = None,
) -> dict[str, Any]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    total_replaced = 0
    unresolved: set[str] = set()

    def _xform_spans(text: str) -> list[tuple[int, int, str]]:
        nonlocal total_replaced
        if not text or "#PII_" not in text:
            return []
        from .pii import TOKEN_RE

        repls: list[tuple[int, int, str]] = []
        for m in TOKEN_RE.finditer(text):
            tok = m.group(0)
            entry = vault.reverse.get(tok)
            if irreversible_style:
                total_replaced += 1
                if entry is not None:
                    from .pii import redact_value

                    repls.append((m.start(), m.end(), redact_value(entry["category"], entry["raw"], style=irreversible_style)))
                else:
                    repls.append((m.start(), m.end(), "***"))
            else:
                if entry is not None:
                    total_replaced += 1
                    repls.append((m.start(), m.end(), entry["raw"]))
                else:
                    unresolved.add(tok)
        return repls

    with zipfile.ZipFile(masked_path, "r") as zin:
        modified: dict[str, bytes] = {}
        for name in zin.namelist():
            if not DOCX_TEXT_PARTS_RE.match(name):
                continue
            raw = zin.read(name)
            root = parse_xml(raw)
            changed = False
            for elem in root.iter():
                if local_name(elem.tag) != "p":
                    continue
                text, t_entries = _collect_paragraph_segments(elem)
                if "#PII_" not in text or not t_entries:
                    continue
                repls = _xform_spans(text)
                if repls:
                    _apply_replacements_to_t_entries(text, t_entries, repls)
                    changed = True
            if changed:
                modified[name] = serialize_xml(root, raw)

        tmp_out = output_path.with_suffix(output_path.suffix + ".tmp")
        with zipfile.ZipFile(tmp_out, "w", compression=zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                if item.filename in modified:
                    zout.writestr(item, modified[item.filename])
                else:
                    zout.writestr(item, zin.read(item.filename))
        zin.close()  # Windows: release the source handle before replacing it
        os.replace(tmp_out, output_path)

    return {
        "output_path": str(output_path),
        "restored_count": total_replaced,
        "unresolved_tokens": sorted(unresolved),
    }


def inspect_docx(
    path: Path,
    paragraph_start: int = 1,
    paragraph_end: int = 100,
) -> dict[str, Any]:
    paragraphs: list[dict[str, str]] = []
    tables: list[list[list[str]]] = []
    headers_footers: dict[str, list[str]] = {}

    with zipfile.ZipFile(path, "r") as zf:
        if "word/document.xml" in zf.namelist():
            root = parse_xml(zf.read("word/document.xml"))
            body = None
            for ch in root:
                if local_name(ch.tag) == "body":
                    body = ch
                    break
            target_root = body if body is not None else root
            for ch in target_root:
                ln = local_name(ch.tag)
                if ln == "p":
                    txt, _ = _collect_paragraph_segments(ch)
                    if txt.strip():
                        style = ""
                        for ppr in ch:
                            if local_name(ppr.tag) == "pPr":
                                for st in ppr:
                                    if local_name(st.tag) == "pStyle":
                                        style = st.attrib.get(f"{{{W_NS}}}val") or st.attrib.get("w:val", "")
                        paragraphs.append({"style": style, "text": txt})
                elif ln == "tbl":
                    tbl_rows: list[list[str]] = []
                    for tr in ch:
                        if local_name(tr.tag) == "tr":
                            tbl_rows.append([_table_cell_text(tc) for tc in tr if local_name(tc.tag) == "tc"])
                    tables.append(tbl_rows)

        for name in sorted(zf.namelist()):
            if re.match(r"^word/(?:header|footer)\d*\.xml$", name):
                hf_root = parse_xml(zf.read(name))
                lines = []
                for p in hf_root.iter():
                    if local_name(p.tag) == "p":
                        t, _ = _collect_paragraph_segments(p)
                        if t.strip():
                            lines.append(t)
                if lines:
                    headers_footers[Path(name).stem] = lines

    start_i = max(0, paragraph_start - 1)
    end_i = min(len(paragraphs), paragraph_end)
    return {
        "format": "docx",
        "total_paragraphs": len(paragraphs),
        "paragraph_start": start_i + 1,
        "paragraph_end": end_i,
        "paragraphs": paragraphs[start_i:end_i],
        "total_tables": len(tables),
        "tables": tables,
        "headers_footers": headers_footers,
    }


def _set_tc_text(tc_elem: ET.Element, new_text: str) -> None:
    ns_prefix = f"{{{W_NS}}}" if "}" in tc_elem.tag else ""
    paras = [ch for ch in tc_elem if local_name(ch.tag) == "p"]
    if not paras:
        p = ET.SubElement(tc_elem, f"{ns_prefix}p")
        r = ET.SubElement(p, f"{ns_prefix}r")
        t = ET.SubElement(r, f"{ns_prefix}t")
        t.text = new_text
        ensure_xml_space(t, new_text)
        return
    p0 = paras[0]
    t_nodes = [n for n in p0.iter() if local_name(n.tag) == "t"]
    if t_nodes:
        t_nodes[0].text = new_text
        ensure_xml_space(t_nodes[0], new_text)
        for extra in t_nodes[1:]:
            extra.text = ""
    else:
        r = ET.SubElement(p0, f"{ns_prefix}r")
        t = ET.SubElement(r, f"{ns_prefix}t")
        t.text = new_text
        ensure_xml_space(t, new_text)
    for extra_p in paras[1:]:
        for n in extra_p.iter():
            if local_name(n.tag) == "t":
                n.text = ""


def edit_docx_file(
    source_path: Path,
    output_path: Path,
    *,
    replacements: Sequence[dict[str, str]] = (),
    table_updates: Sequence[dict[str, Any]] = (),
    append_paragraphs: Sequence[str] = (),
    append_table: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Edit a masked .docx template (find/replace, table cells, append text/table)."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    replaced_hits = 0
    table_edits = 0

    with zipfile.ZipFile(source_path, "r") as zin:
        modified: dict[str, bytes] = {}
        for name in zin.namelist():
            if not DOCX_TEXT_PARTS_RE.match(name):
                continue
            raw = zin.read(name)
            root = parse_xml(raw)
            changed = False

            if replacements:
                for p_elem in root.iter():
                    if local_name(p_elem.tag) != "p":
                        continue
                    text, t_entries = _collect_paragraph_segments(p_elem)
                    if not text or not t_entries:
                        continue
                    span_repls: list[tuple[int, int, str]] = []
                    for item in replacements:
                        needle = str(item.get("find", ""))
                        repl = str(item.get("replace", ""))
                        if not needle:
                            continue
                        start = 0
                        while True:
                            idx = text.find(needle, start)
                            if idx < 0:
                                break
                            span_repls.append((idx, idx + len(needle), repl))
                            replaced_hits += 1
                            start = idx + len(needle)
                    if span_repls:
                        # Remove overlapping finds deterministically (keep earliest).
                        span_repls.sort(key=lambda x: x[0])
                        dedup: list[tuple[int, int, str]] = []
                        last_end = -1
                        for s, e, r in span_repls:
                            if s >= last_end:
                                dedup.append((s, e, r))
                                last_end = e
                        _apply_replacements_to_t_entries(text, t_entries, dedup)
                        changed = True

            if name == "word/document.xml":
                body = None
                for ch in root:
                    if local_name(ch.tag) == "body":
                        body = ch
                        break
                target_root = body if body is not None else root
                ns_prefix = f"{{{W_NS}}}" if "}" in root.tag else ""

                if table_updates:
                    doc_tables = [ch for ch in target_root if local_name(ch.tag) == "tbl"]
                    for upd in table_updates:
                        t_idx = int(upd.get("table_index", 0))
                        r_idx = int(upd["row"])
                        c_idx = int(upd["col"])
                        val = str(upd.get("value", ""))
                        if not (0 <= t_idx < len(doc_tables)):
                            raise ValueError(f"table_index out of range: {t_idx}")
                        trs = [ch for ch in doc_tables[t_idx] if local_name(ch.tag) == "tr"]
                        if not (0 <= r_idx < len(trs)):
                            raise ValueError(f"row out of range: {r_idx}")
                        tcs = [ch for ch in trs[r_idx] if local_name(ch.tag) == "tc"]
                        if not (0 <= c_idx < len(tcs)):
                            raise ValueError(f"col out of range: {c_idx}")
                        _set_tc_text(tcs[c_idx], val)
                        table_edits += 1
                        changed = True

                # Locate sectPr so appended paragraphs/tables stay before <w:sectPr>.
                sect_idx = len(list(target_root))
                for idx, ch in enumerate(target_root):
                    if local_name(ch.tag) == "sectPr":
                        sect_idx = idx
                        break

                for p_text in append_paragraphs:
                    p_el = ET.Element(f"{ns_prefix}p")
                    r_el = ET.SubElement(p_el, f"{ns_prefix}r")
                    t_el = ET.SubElement(r_el, f"{ns_prefix}t")
                    t_el.text = str(p_text)
                    ensure_xml_space(t_el, str(p_text))
                    target_root.insert(sect_idx, p_el)
                    sect_idx += 1
                    changed = True

                if append_table:
                    tbl_el = ET.Element(f"{ns_prefix}tbl")
                    tbl_pr = ET.SubElement(tbl_el, f"{ns_prefix}tblPr")
                    borders = ET.SubElement(tbl_pr, f"{ns_prefix}tblBorders")
                    for bside in ("top", "left", "bottom", "right", "insideH", "insideV"):
                        ET.SubElement(
                            borders,
                            f"{ns_prefix}{bside}",
                            **{
                                f"{ns_prefix}val": "single",
                                f"{ns_prefix}sz": "4",
                                f"{ns_prefix}space": "0",
                                f"{ns_prefix}color": "auto",
                            },
                        )
                    all_rows: list[Sequence[Any]] = []
                    if append_table.get("headers"):
                        all_rows.append(append_table["headers"])
                    all_rows.extend(append_table.get("rows", []))
                    for row_vals in all_rows:
                        tr_el = ET.SubElement(tbl_el, f"{ns_prefix}tr")
                        for cell_val in row_vals:
                            tc_el = ET.SubElement(tr_el, f"{ns_prefix}tc")
                            p_el = ET.SubElement(tc_el, f"{ns_prefix}p")
                            r_el = ET.SubElement(p_el, f"{ns_prefix}r")
                            t_el = ET.SubElement(r_el, f"{ns_prefix}t")
                            s = "" if cell_val is None else str(cell_val)
                            t_el.text = s
                            ensure_xml_space(t_el, s)
                    target_root.insert(sect_idx, tbl_el)
                    changed = True

            if changed:
                modified[name] = serialize_xml(root, raw)

        tmp_out = output_path.with_suffix(output_path.suffix + ".tmp")
        with zipfile.ZipFile(tmp_out, "w", compression=zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                if item.filename in modified:
                    zout.writestr(item, modified[item.filename])
                else:
                    zout.writestr(item, zin.read(item.filename))
        zin.close()  # Windows: release the source handle before replacing it
        os.replace(tmp_out, output_path)

    return {
        "output_path": str(output_path),
        "replacements_applied": replaced_hits,
        "table_cells_updated": table_edits,
        "appended_paragraphs": len(append_paragraphs),
        "appended_table": bool(append_table),
    }


def create_docx_file(
    output_path: Path,
    *,
    title: str | None = None,
    blocks: Sequence[dict[str, Any]] = (),
) -> dict[str, Any]:
    """Create a clean, valid .docx document from paragraphs/headings/tables.

    Each block in `blocks` can be:
      {"type": "heading", "text": "...", "level": 1}
      {"type": "paragraph", "text": "..."}
      {"type": "table", "headers": [...], "rows": [[...], ...]}
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    ct_ns = "http://schemas.openxmlformats.org/package/2006/content-types"
    pkg_rel_ns = "http://schemas.openxmlformats.org/package/2006/relationships"

    ET.register_namespace("w", W_NS)
    doc = ET.Element(f"{{{W_NS}}}document")
    body = ET.SubElement(doc, f"{{{W_NS}}}body")

    def add_para(text: str, style: str | None = None) -> None:
        p = ET.SubElement(body, f"{{{W_NS}}}p")
        if style:
            ppr = ET.SubElement(p, f"{{{W_NS}}}pPr")
            ET.SubElement(ppr, f"{{{W_NS}}}pStyle", **{f"{{{W_NS}}}val": style})
        r = ET.SubElement(p, f"{{{W_NS}}}r")
        t = ET.SubElement(r, f"{{{W_NS}}}t")
        t.text = text
        ensure_xml_space(t, text)

    if title:
        add_para(str(title), style="Heading1")

    para_cnt = 1 if title else 0
    tbl_cnt = 0
    for blk in blocks:
        btype = str(blk.get("type", "paragraph")).lower()
        if btype == "heading":
            lvl = max(1, min(3, int(blk.get("level", 1))))
            add_para(str(blk.get("text", "")), style=f"Heading{lvl}")
            para_cnt += 1
        elif btype == "table":
            tbl_el = ET.SubElement(body, f"{{{W_NS}}}tbl")
            tbl_pr = ET.SubElement(tbl_el, f"{{{W_NS}}}tblPr")
            borders = ET.SubElement(tbl_pr, f"{{{W_NS}}}tblBorders")
            for bside in ("top", "left", "bottom", "right", "insideH", "insideV"):
                ET.SubElement(
                    borders,
                    f"{{{W_NS}}}{bside}",
                    **{
                        f"{{{W_NS}}}val": "single",
                        f"{{{W_NS}}}sz": "4",
                        f"{{{W_NS}}}space": "0",
                        f"{{{W_NS}}}color": "BFBFBF",
                    },
                )
            rows_all: list[tuple[bool, Sequence[Any]]] = []
            if blk.get("headers"):
                rows_all.append((True, blk["headers"]))
            for r_vals in blk.get("rows", []):
                rows_all.append((False, r_vals))
            for is_hdr, row_vals in rows_all:
                tr_el = ET.SubElement(tbl_el, f"{{{W_NS}}}tr")
                for cell_val in row_vals:
                    tc_el = ET.SubElement(tr_el, f"{{{W_NS}}}tc")
                    if is_hdr:
                        tc_pr = ET.SubElement(tc_el, f"{{{W_NS}}}tcPr")
                        ET.SubElement(
                            tc_pr,
                            f"{{{W_NS}}}shd",
                            **{f"{{{W_NS}}}val": "clear", f"{{{W_NS}}}color": "auto", f"{{{W_NS}}}fill": "D9E1F2"},
                        )
                    p_el = ET.SubElement(tc_el, f"{{{W_NS}}}p")
                    r_el = ET.SubElement(p_el, f"{{{W_NS}}}r")
                    if is_hdr:
                        rpr = ET.SubElement(r_el, f"{{{W_NS}}}rPr")
                        ET.SubElement(rpr, f"{{{W_NS}}}b")
                    t_el = ET.SubElement(r_el, f"{{{W_NS}}}t")
                    s = "" if cell_val is None else str(cell_val)
                    t_el.text = s
                    ensure_xml_space(t_el, s)
            tbl_cnt += 1
        else:
            add_para(str(blk.get("text", "")))
            para_cnt += 1

    ET.SubElement(body, f"{{{W_NS}}}sectPr")
    doc_bytes = serialize_xml(doc)

    styles_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>'
        '<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/>'
        '<w:basedOn w:val="Normal"/><w:rPr><w:b/><w:sz w:val="32"/></w:rPr></w:style>'
        '<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/>'
        '<w:basedOn w:val="Normal"/><w:rPr><w:b/><w:sz w:val="26"/></w:rPr></w:style>'
        '<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/>'
        '<w:basedOn w:val="Normal"/><w:rPr><w:b/><w:sz w:val="22"/></w:rPr></w:style>'
        '</w:styles>'
    ).encode("utf-8")

    ET.register_namespace("", ct_ns)
    ct = ET.Element(f"{{{ct_ns}}}Types")
    ET.SubElement(ct, f"{{{ct_ns}}}Default", Extension="rels", ContentType="application/vnd.openxmlformats-package.relationships+xml")
    ET.SubElement(ct, f"{{{ct_ns}}}Default", Extension="xml", ContentType="application/xml")
    ET.SubElement(ct, f"{{{ct_ns}}}Override", PartName="/word/document.xml", ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml")
    ET.SubElement(ct, f"{{{ct_ns}}}Override", PartName="/word/styles.xml", ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml")
    ct_bytes = serialize_xml(ct)

    ET.register_namespace("", pkg_rel_ns)
    root_rels = ET.Element(f"{{{pkg_rel_ns}}}Relationships")
    ET.SubElement(
        root_rels,
        f"{{{pkg_rel_ns}}}Relationship",
        Id="rId1",
        Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument",
        Target="word/document.xml",
    )
    root_rels_bytes = serialize_xml(root_rels)

    ET.register_namespace("", pkg_rel_ns)
    doc_rels = ET.Element(f"{{{pkg_rel_ns}}}Relationships")
    ET.SubElement(
        doc_rels,
        f"{{{pkg_rel_ns}}}Relationship",
        Id="rId1",
        Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles",
        Target="styles.xml",
    )
    doc_rels_bytes = serialize_xml(doc_rels)

    tmp_out = output_path.with_suffix(output_path.suffix + ".tmp")
    with zipfile.ZipFile(tmp_out, "w", compression=zipfile.ZIP_DEFLATED) as zout:
        zout.writestr("[Content_Types].xml", ct_bytes)
        zout.writestr("_rels/.rels", root_rels_bytes)
        zout.writestr("word/_rels/document.xml.rels", doc_rels_bytes)
        zout.writestr("word/styles.xml", styles_xml)
        zout.writestr("word/document.xml", doc_bytes)
    os.replace(tmp_out, output_path)
    return {
        "output_path": str(output_path),
        "paragraphs": para_cnt,
        "tables": tbl_cnt,
    }
