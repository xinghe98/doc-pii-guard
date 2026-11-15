"""Lossless OOXML (.xlsx / .xlsm) PII masking, restoration, inspection, editing, and creation."""

from __future__ import annotations

import os
import re
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Sequence

from .pii import DEFAULT_CATEGORIES, TOKEN_RE, apply_replacements, find_pii_spans
from .table_ops import detect_header_row
from .vault import PIIVault
from .xml_utils import (
    ensure_xml_space,
    iter_children_by_local,
    local_name,
    parse_xml,
    serialize_xml,
)

MAIN_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PKG_REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
CT_NS = "http://schemas.openxmlformats.org/package/2006/content-types"

CELL_REF_RE = re.compile(r"^([A-Za-z]+)(\d+)$")


def col_letters_to_idx(letters: str) -> int:
    idx = 0
    for ch in letters.upper():
        idx = idx * 26 + (ord(ch) - ord("A") + 1)
    return idx - 1


def idx_to_col_letters(idx: int) -> str:
    n = idx + 1
    chars: list[str] = []
    while n > 0:
        n, rem = divmod(n - 1, 26)
        chars.append(chr(ord("A") + rem))
    return "".join(reversed(chars))


def parse_cell_ref(ref: str) -> tuple[int, int] | None:
    m = CELL_REF_RE.match(ref.strip())
    if not m:
        return None
    return int(m.group(2)) - 1, col_letters_to_idx(m.group(1))


def _si_text(si_elem: ET.Element) -> str:
    parts: list[str] = []
    for child in si_elem:
        ln = local_name(child.tag)
        if ln == "t":
            if child.text:
                parts.append(child.text)
        elif ln == "r":
            for sub in child:
                if local_name(sub.tag) == "t" and sub.text:
                    parts.append(sub.text)
    return "".join(parts)


def _load_shared_strings(zf: zipfile.ZipFile) -> tuple[ET.Element | None, bytes | None, list[str]]:
    if "xl/sharedStrings.xml" not in zf.namelist():
        return None, None, []
    raw = zf.read("xl/sharedStrings.xml")
    root = parse_xml(raw)
    strings = [_si_text(si) for si in iter_children_by_local(root, "si")]
    return root, raw, strings


def _get_sheet_entries(zf: zipfile.ZipFile) -> list[tuple[str, str]]:
    """Return ordered list of (sheet_name, zip_entry_path)."""
    wb_raw = zf.read("xl/workbook.xml")
    wb_root = parse_xml(wb_raw)

    rel_map: dict[str, str] = {}
    if "xl/_rels/workbook.xml.rels" in zf.namelist():
        rels_root = parse_xml(zf.read("xl/_rels/workbook.xml.rels"))
        for rel in rels_root:
            if local_name(rel.tag) == "Relationship":
                rid = rel.attrib.get("Id", "")
                target = rel.attrib.get("Target", "")
                if target.startswith("/"):
                    target_path = target.lstrip("/")
                elif target.startswith("xl/"):
                    target_path = target
                else:
                    target_path = f"xl/{target.lstrip('./')}"
                rel_map[rid] = target_path

    sheets: list[tuple[str, str]] = []
    for elem in wb_root.iter():
        if local_name(elem.tag) == "sheet":
            name = elem.attrib.get("name", "Sheet")
            rid = elem.attrib.get(f"{{{REL_NS}}}id") or elem.attrib.get("r:id", "")
            target = rel_map.get(rid, "")
            if target and target in zf.namelist():
                sheets.append((name, target))
    if not sheets:
        # Fallback to sorted worksheet XMLs.
        for name in sorted(zf.namelist()):
            if name.startswith("xl/worksheets/sheet") and name.endswith(".xml"):
                sheets.append((Path(name).stem, name))
    return sheets


def _extract_cell_text(c_elem: ET.Element, shared_strings: list[str]) -> tuple[str, bool]:
    """Return (text_value, is_numeric_raw)."""
    ctype = c_elem.attrib.get("t", "n")
    has_formula = False
    v_text = ""
    is_text_parts: list[str] = []

    for child in c_elem:
        ln = local_name(child.tag)
        if ln == "f":
            has_formula = True
        elif ln == "v" and child.text is not None:
            v_text = child.text
        elif ln == "is":
            is_text_parts.append(_si_text(child))

    if ctype == "s":
        try:
            idx = int(v_text)
            return (shared_strings[idx] if 0 <= idx < len(shared_strings) else ""), False
        except ValueError:
            return "", False
    if ctype == "inlineStr":
        return "".join(is_text_parts), False
    if ctype in ("str", "e"):
        return v_text, False
    if ctype == "b":
        return ("TRUE" if v_text == "1" else "FALSE"), False
    # Numeric cell.
    if has_formula and not v_text:
        return "", False
    return v_text, True


def _sheet_to_grid(sheet_root: ET.Element, shared_strings: list[str]) -> tuple[list[list[str]], dict[tuple[int, int], tuple[ET.Element, str, bool]]]:
    """Parse worksheet XML into a dense 2D string grid + cell map."""
    cell_map: dict[tuple[int, int], tuple[ET.Element, str, bool]] = {}
    max_r = -1
    max_c = -1

    sheet_data = None
    for child in sheet_root:
        if local_name(child.tag) == "sheetData":
            sheet_data = child
            break
    if sheet_data is None:
        return [], cell_map

    fallback_row = 0
    for row_elem in iter_children_by_local(sheet_data, "row"):
        r_attr = row_elem.attrib.get("r")
        r_idx = int(r_attr) - 1 if r_attr and r_attr.isdigit() else fallback_row
        fallback_row = r_idx + 1
        fallback_col = 0
        for c_elem in iter_children_by_local(row_elem, "c"):
            ref = c_elem.attrib.get("r", "")
            parsed = parse_cell_ref(ref) if ref else None
            if parsed:
                cr, cc = parsed
            else:
                cr, cc = r_idx, fallback_col
            fallback_col = cc + 1
            text, is_num = _extract_cell_text(c_elem, shared_strings)
            cell_map[(cr, cc)] = (c_elem, text, is_num)
            if cr > max_r:
                max_r = cr
            if cc > max_c:
                max_c = cc

    if max_r < 0 or max_c < 0:
        return [], cell_map

    grid = [[""] * (max_c + 1) for _ in range(max_r + 1)]
    for (r, c), (_, text, _) in cell_map.items():
        grid[r][c] = text
    return grid, cell_map


def _set_cell_string_value(
    c_elem: ET.Element,
    new_text: str,
    sst_root: ET.Element | None,
    shared_strings: list[str],
    sst_cache: dict[str, int],
) -> None:
    """Update a worksheet <c> cell to hold `new_text` while preserving style `s`."""
    ns_prefix = ""
    if "}" in c_elem.tag:
        ns_prefix = c_elem.tag.split("}", 1)[0] + "}"

    has_formula = any(local_name(ch.tag) == "f" for ch in c_elem)
    if has_formula:
        c_elem.set("t", "str")
        v_el = None
        for ch in c_elem:
            if local_name(ch.tag) == "v":
                v_el = ch
                break
        if v_el is None:
            v_el = ET.SubElement(c_elem, f"{ns_prefix}v")
        v_el.text = new_text
        ensure_xml_space(v_el, new_text)
        return

    # Remove inlineStr <is> if present.
    for ch in list(c_elem):
        if local_name(ch.tag) in ("is", "v"):
            c_elem.remove(ch)

    if sst_root is not None:
        if new_text not in sst_cache:
            si = ET.SubElement(sst_root, f"{ns_prefix}si")
            t_el = ET.SubElement(si, f"{ns_prefix}t")
            t_el.text = new_text
            ensure_xml_space(t_el, new_text)
            idx = len(shared_strings)
            shared_strings.append(new_text)
            sst_cache[new_text] = idx
        else:
            idx = sst_cache[new_text]
        c_elem.set("t", "s")
        v_el = ET.SubElement(c_elem, f"{ns_prefix}v")
        v_el.text = str(idx)
    else:
        c_elem.set("t", "inlineStr")
        is_el = ET.SubElement(c_elem, f"{ns_prefix}is")
        t_el = ET.SubElement(is_el, f"{ns_prefix}t")
        t_el.text = new_text
        ensure_xml_space(t_el, new_text)


def _rewrite_t_nodes_in_elem(elem: ET.Element, transform_fn: Any) -> None:
    """Apply `transform_fn(text) -> new_text` across <t> elements under `elem`."""
    # Handle <r><t>...</t></r> or direct <t>...</t> by coalescing text if needed.
    t_nodes = [node for node in elem.iter() if local_name(node.tag) == "t"]
    if not t_nodes:
        return
    combined = "".join(n.text or "" for n in t_nodes)
    updated = transform_fn(combined)
    if updated == combined:
        return
    t_nodes[0].text = updated
    ensure_xml_space(t_nodes[0], updated)
    for extra in t_nodes[1:]:
        extra.text = ""


def mask_xlsx_file(
    source_path: Path,
    masked_path: Path,
    vault: PIIVault,
    *,
    extra_name_columns: Sequence[str] = (),
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

    with zipfile.ZipFile(source_path, "r") as zin:
        names = zin.namelist()
        sst_root, sst_raw, shared_strings = _load_shared_strings(zin)
        sst_cache: dict[str, int] = {}
        sheet_entries = _get_sheet_entries(zin)

        parsed_sheets: list[dict[str, Any]] = []
        for s_name, s_path in sheet_entries:
            s_raw = zin.read(s_path)
            s_root = parse_xml(s_raw)
            grid, cell_map = _sheet_to_grid(s_root, shared_strings)
            hdr_idx, col_cats = detect_header_row(grid)
            if extra_name_columns and hdr_idx < len(grid):
                extra_set = {c.strip().lower() for c in extra_name_columns if c.strip()}
                for c_idx, cell in enumerate(grid[hdr_idx]):
                    if cell.strip().lower() in extra_set:
                        col_cats[c_idx] = "NAME"
            parsed_sheets.append({
                "name": s_name,
                "path": s_path,
                "raw": s_raw,
                "root": s_root,
                "grid": grid,
                "cell_map": cell_map,
                "hdr_idx": hdr_idx,
                "col_cats": col_cats,
            })

        # Pass 1: column-aware + pattern detection across all sheets.
        sheet_texts: dict[tuple[str, int, int], str] = {}
        for sh in parsed_sheets:
            hdr_idx = sh["hdr_idx"]
            col_cats = sh["col_cats"]
            grid = sh["grid"]
            for (r_idx, c_idx), (c_elem, text, is_num) in sh["cell_map"].items():
                if not text:
                    continue
                col_cat = col_cats.get(c_idx) if r_idx > hdr_idx else None
                if col_cat and r_idx > hdr_idx and hdr_idx < len(grid) and c_idx < len(grid[hdr_idx]):
                    if text.strip() == grid[hdr_idx][c_idx].strip():
                        col_cat = None
                # Clean trailing .0 on numeric phone/id cells.
                cand_text = text
                if is_num and col_cat in ("PHONE", "ID_CARD", "BANK_CARD") and cand_text.endswith(".0"):
                    cand_text = cand_text[:-2]
                spans = find_pii_spans(
                    cand_text,
                    column_category=col_cat,
                    known_names=vault.known_names,
                    extra_names=extra_names,
                    exclude_words=exclude_words,
                    categories=categories,
                )
                masked_text, _ = apply_replacements(cand_text, spans, alloc)
                sheet_texts[(sh["path"], r_idx, c_idx)] = masked_text if spans else text

        # Pass 2: cross-reference newly discovered names across all cells & sheets.
        modified_sheets: dict[str, bytes] = {}
        sheet_summaries: list[dict[str, Any]] = []
        for sh in parsed_sheets:
            masked_grid = [list(r) for r in sh["grid"]]
            for (r_idx, c_idx), (c_elem, orig_text, _) in sh["cell_map"].items():
                cur_text = sheet_texts.get((sh["path"], r_idx, c_idx), orig_text)
                if not cur_text:
                    continue
                spans = find_pii_spans(
                    cur_text,
                    column_category=None,
                    known_names=vault.known_names,
                    extra_names=extra_names,
                    exclude_words=exclude_words,
                    categories=categories,
                )
                final_text, _ = apply_replacements(cur_text, spans, alloc)
                if r_idx < len(masked_grid) and c_idx < len(masked_grid[r_idx]):
                    masked_grid[r_idx][c_idx] = final_text
                if final_text != orig_text:
                    _set_cell_string_value(c_elem, final_text, sst_root, shared_strings, sst_cache)

            modified_sheets[sh["path"]] = serialize_xml(sh["root"], sh["raw"])
            hdr_idx = sh["hdr_idx"]
            headers = masked_grid[hdr_idx] if hdr_idx < len(masked_grid) else []
            sheet_summaries.append({
                "name": sh["name"],
                "rows": len(masked_grid),
                "cols": max((len(r) for r in masked_grid), default=0),
                "header_row": hdr_idx + 1,
                "headers": headers,
            })

        # Also mask sheet names in workbook.xml, comments, and core.xml metadata.
        modified_extra: dict[str, bytes] = {}
        sheet_name_map: dict[str, str] = {}
        if "xl/workbook.xml" in names:
            wb_raw = zin.read("xl/workbook.xml")
            wb_root = parse_xml(wb_raw)
            wb_changed = False
            for elem in wb_root.iter():
                if local_name(elem.tag) == "sheet":
                    sname = elem.attrib.get("name", "")
                    spans = find_pii_spans(
                        sname,
                        known_names=vault.known_names,
                        extra_names=extra_names,
                        exclude_words=exclude_words,
                        categories=categories,
                    )
                    if spans:
                        new_sname, _ = apply_replacements(sname, spans, alloc)
                        # Excel sheet names max 31 chars; trim safely if needed.
                        trimmed = new_sname[:31]
                        elem.set("name", trimmed)
                        sheet_name_map[sname] = trimmed
                        wb_changed = True
            if wb_changed:
                modified_extra["xl/workbook.xml"] = serialize_xml(wb_root, wb_raw)
                for ss in sheet_summaries:
                    if ss["name"] in sheet_name_map:
                        ss["name"] = sheet_name_map[ss["name"]]

        for entry_name in names:
            if (entry_name.startswith("xl/comments") or entry_name.startswith("xl/threadedComments/")) and entry_name.endswith(".xml"):
                c_raw = zin.read(entry_name)
                c_root = parse_xml(c_raw)

                def _mask_comment(txt: str) -> str:
                    sp = find_pii_spans(
                        txt,
                        known_names=vault.known_names,
                        extra_names=extra_names,
                        exclude_words=exclude_words,
                        categories=categories,
                    )
                    res, _ = apply_replacements(txt, sp, alloc)
                    return res

                for node in c_root.iter():
                    if local_name(node.tag) in ("text", "t"):
                        if local_name(node.tag) == "text":
                            _rewrite_t_nodes_in_elem(node, _mask_comment)
                modified_extra[entry_name] = serialize_xml(c_root, c_raw)

        if "docProps/core.xml" in names:
            core_raw = zin.read("docProps/core.xml")
            core_root = parse_xml(core_raw)
            core_changed = False
            for node in core_root.iter():
                if local_name(node.tag) in ("creator", "lastModifiedBy") and node.text and node.text.strip():
                    node.text = "REDACTED"
                    core_changed = True
            if core_changed:
                modified_extra["docProps/core.xml"] = serialize_xml(core_root, core_raw)

        if sst_root is not None:
            sst_root.set("count", str(len(shared_strings)))
            sst_root.set("uniqueCount", str(len(shared_strings)))
            modified_extra["xl/sharedStrings.xml"] = serialize_xml(sst_root, sst_raw)

        tmp_out = masked_path.with_suffix(masked_path.suffix + ".tmp")
        with zipfile.ZipFile(tmp_out, "w", compression=zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                if item.filename in modified_sheets:
                    zout.writestr(item, modified_sheets[item.filename])
                elif item.filename in modified_extra:
                    zout.writestr(item, modified_extra[item.filename])
                else:
                    zout.writestr(item, zin.read(item.filename))
        zin.close()  # Windows: release the source handle before replacing it
        os.replace(tmp_out, masked_path)

    return {
        "sheets": sheet_summaries,
        "pii_counts": counts,
    }


def restore_xlsx_file(
    masked_path: Path,
    output_path: Path,
    vault: PIIVault,
    *,
    irreversible_style: str | None = None,
) -> dict[str, Any]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    total_replaced = 0
    unresolved: set[str] = set()

    def _xform(text: str) -> str:
        nonlocal total_replaced
        if not text or "#PII_" not in text:
            return text
        if irreversible_style:
            new_text, cnt = vault.redact_text_tokens(text, style=irreversible_style)
            total_replaced += cnt
            return new_text
        new_text, cnt, unres = vault.restore_text(text)
        total_replaced += cnt
        unresolved.update(unres)
        return new_text

    with zipfile.ZipFile(masked_path, "r") as zin:
        names = zin.namelist()
        modified: dict[str, bytes] = {}

        if "xl/sharedStrings.xml" in names:
            raw = zin.read("xl/sharedStrings.xml")
            root = parse_xml(raw)
            for si in iter_children_by_local(root, "si"):
                # Replace inside individual <t> nodes or across <r><t> if token was split across runs.
                t_nodes = [n for n in si.iter() if local_name(n.tag) == "t"]
                if not t_nodes:
                    continue
                if len(t_nodes) == 1:
                    if t_nodes[0].text:
                        nt = _xform(t_nodes[0].text)
                        t_nodes[0].text = nt
                        ensure_xml_space(t_nodes[0], nt)
                else:
                    combined = "".join(n.text or "" for n in t_nodes)
                    if "#PII_" in combined:
                        # First try per-node if tokens aren't split; if still contains #PII_ after per-node, coalesce.
                        all_clean = True
                        for n in t_nodes:
                            if n.text and "#PII_" in n.text:
                                n.text = _xform(n.text)
                                ensure_xml_space(n, n.text)
                                if TOKEN_RE.search(n.text):
                                    all_clean = False
                        if not all_clean or TOKEN_RE.search("".join(n.text or "" for n in t_nodes)):
                            _rewrite_t_nodes_in_elem(si, _xform)
            modified["xl/sharedStrings.xml"] = serialize_xml(root, raw)

        for entry_name in names:
            if entry_name.startswith("xl/worksheets/sheet") and entry_name.endswith(".xml"):
                raw = zin.read(entry_name)
                root = parse_xml(raw)
                changed = False
                for node in root.iter():
                    ln = local_name(node.tag)
                    if ln == "c":
                        ctype = node.attrib.get("t", "n")
                        for ch in node:
                            cln = local_name(ch.tag)
                            if cln == "is":
                                before = _si_text(ch)
                                if "#PII_" in before:
                                    _rewrite_t_nodes_in_elem(ch, _xform)
                                    changed = True
                            elif cln == "v" and ctype == "str" and ch.text and "#PII_" in ch.text:
                                ch.text = _xform(ch.text)
                                ensure_xml_space(ch, ch.text)
                                changed = True
                            elif cln == "f" and ch.text and "#PII_" in ch.text:
                                ch.text = _xform(ch.text)
                                changed = True
                if changed:
                    modified[entry_name] = serialize_xml(root, raw)
            elif (entry_name.startswith("xl/comments") or entry_name.startswith("xl/threadedComments/")) and entry_name.endswith(".xml"):
                raw = zin.read(entry_name)
                root = parse_xml(raw)
                for node in root.iter():
                    if local_name(node.tag) == "text":
                        _rewrite_t_nodes_in_elem(node, _xform)
                modified[entry_name] = serialize_xml(root, raw)
            elif entry_name == "xl/workbook.xml":
                raw = zin.read(entry_name)
                root = parse_xml(raw)
                changed = False
                for elem in root.iter():
                    if local_name(elem.tag) == "sheet":
                        sname = elem.attrib.get("name", "")
                        if "#PII_" in sname:
                            elem.set("name", _xform(sname)[:31])
                            changed = True
                if changed:
                    modified[entry_name] = serialize_xml(root, raw)

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


def read_xlsx_sheet_table(
    path: Path,
    sheet_name: str | None = None,
) -> tuple[str, list[str], list[list[str]], int, list[str]]:
    """Read a sheet into (resolved_sheet_name, headers, data_rows, header_row_1based, all_sheet_names)."""
    with zipfile.ZipFile(path, "r") as zf:
        _, _, shared_strings = _load_shared_strings(zf)
        entries = _get_sheet_entries(zf)
        all_names = [n for n, _ in entries]
        if not entries:
            raise ValueError(f"No worksheets found in {path}")
        target = entries[0]
        if sheet_name:
            matched = [e for e in entries if e[0] == sheet_name]
            if not matched:
                raise ValueError(f"Sheet '{sheet_name}' not found. Available: {all_names}")
            target = matched[0]
        s_root = parse_xml(zf.read(target[1]))
        grid, _ = _sheet_to_grid(s_root, shared_strings)
        if not grid:
            return target[0], [], [], 1, all_names
        hdr_idx, _ = detect_header_row(grid)
        headers = grid[hdr_idx] if hdr_idx < len(grid) else []
        data_rows = grid[hdr_idx + 1 :]
        return target[0], headers, data_rows, hdr_idx + 1, all_names


def inspect_xlsx(
    path: Path,
    sheet_name: str | None = None,
    row_start: int = 1,
    row_end: int = 50,
) -> dict[str, Any]:
    with zipfile.ZipFile(path, "r") as zf:
        _, _, shared_strings = _load_shared_strings(zf)
        entries = _get_sheet_entries(zf)
        all_names = [n for n, _ in entries]
        if not entries:
            return {"format": "xlsx", "sheets": [], "rows": []}
        target = entries[0]
        if sheet_name:
            matched = [e for e in entries if e[0] == sheet_name]
            if not matched:
                raise ValueError(f"Sheet '{sheet_name}' not found. Available: {all_names}")
            target = matched[0]
        s_root = parse_xml(zf.read(target[1]))
        grid, _ = _sheet_to_grid(s_root, shared_strings)

    hdr_idx, _ = detect_header_row(grid)
    total_rows = len(grid)
    start_idx = max(0, row_start - 1)
    end_idx = min(total_rows, row_end)
    return {
        "format": path.suffix.lstrip(".").lower(),
        "sheets": all_names,
        "active_sheet": target[0],
        "total_rows": total_rows,
        "total_cols": max((len(r) for r in grid), default=0),
        "header_row": hdr_idx + 1,
        "headers": grid[hdr_idx] if hdr_idx < len(grid) else [],
        "row_start": start_idx + 1,
        "row_end": end_idx,
        "rows": grid[start_idx:end_idx],
    }


def _is_number(val: Any) -> bool:
    if isinstance(val, bool):
        return False
    if isinstance(val, (int, float)):
        return True
    if isinstance(val, str):
        s = val.strip()
        if not s:
            return False
        # Preserve leading-zero strings (e.g. "00123", "010") as text!
        if len(s) > 1 and s[0] == "0" and s[1].isdigit():
            return False
        try:
            float(s)
            return True
        except ValueError:
            return False
    return False


def create_xlsx_file(
    output_path: Path,
    sheets: Sequence[dict[str, Any]],
    *,
    freeze_header: bool = True,
) -> dict[str, Any]:
    """Create a clean, formatted multi-sheet .xlsx workbook using pure Python stdlib.

    Each item in `sheets`:
      {"name": "Sheet1", "headers": [...], "rows": [[...], ...]}
    Strings starting with '=' are written as Excel formulas.
    """
    if not sheets:
        raise ValueError("At least one sheet definition is required")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    shared_strings: list[str] = []
    sst_map: dict[str, int] = {}

    def intern_str(s: str) -> int:
        if s not in sst_map:
            sst_map[s] = len(shared_strings)
            shared_strings.append(s)
        return sst_map[s]

    sheet_xml_bytes: list[tuple[str, bytes]] = []
    summary_sheets: list[dict[str, Any]] = []

    for s_idx, spec in enumerate(sheets, start=1):
        sname = str(spec.get("name") or f"Sheet{s_idx}")[:31]
        headers = [str(h) for h in spec.get("headers", [])]
        rows = spec.get("rows", [])
        all_rows: list[tuple[bool, Sequence[Any]]] = []
        if headers:
            all_rows.append((True, headers))
        for r in rows:
            all_rows.append((False, r))

        max_cols = max((len(r) for _, r in all_rows), default=1)
        col_widths = [10.0] * max_cols
        for _, row_vals in all_rows:
            for c_i, val in enumerate(row_vals):
                if c_i >= max_cols:
                    break
                sval = "" if val is None else str(val)
                # Rough display width heuristic (CJK chars ~ 2 width).
                w = sum(2.0 if "\u4e00" <= ch <= "\u9fff" else 1.05 for ch in sval) + 3.0
                if sval.startswith("="):
                    w = max(w, 12.0)
                col_widths[c_i] = min(48.0, max(col_widths[c_i], w))

        ET.register_namespace("", MAIN_NS)
        ws = ET.Element(f"{{{MAIN_NS}}}worksheet")
        if freeze_header and headers:
            views = ET.SubElement(ws, f"{{{MAIN_NS}}}sheetViews")
            sv = ET.SubElement(views, f"{{{MAIN_NS}}}sheetView", workbookViewId="0")
            ET.SubElement(
                sv,
                f"{{{MAIN_NS}}}pane",
                ySplit="1",
                topLeftCell="A2",
                activePane="bottomLeft",
                state="frozen",
            )
        cols_el = ET.SubElement(ws, f"{{{MAIN_NS}}}cols")
        for c_i, width in enumerate(col_widths, start=1):
            ET.SubElement(
                cols_el,
                f"{{{MAIN_NS}}}col",
                min=str(c_i),
                max=str(c_i),
                width=f"{width:.1f}",
                customWidth="1",
            )
        sdata = ET.SubElement(ws, f"{{{MAIN_NS}}}sheetData")

        for r_i, (is_hdr, row_vals) in enumerate(all_rows, start=1):
            row_el = ET.SubElement(sdata, f"{{{MAIN_NS}}}row", r=str(r_i))
            if is_hdr:
                row_el.set("ht", "22")
                row_el.set("customHeight", "1")
            for c_i, val in enumerate(row_vals):
                ref = f"{idx_to_col_letters(c_i)}{r_i}"
                style_id = "1" if is_hdr else "2"
                if val is None or val == "":
                    ET.SubElement(row_el, f"{{{MAIN_NS}}}c", r=ref, s=style_id)
                    continue
                sval = str(val)
                if not is_hdr and sval.startswith("=") and len(sval) > 1:
                    c_el = ET.SubElement(row_el, f"{{{MAIN_NS}}}c", r=ref, s=style_id)
                    f_el = ET.SubElement(c_el, f"{{{MAIN_NS}}}f")
                    f_el.text = sval[1:]
                elif not is_hdr and _is_number(val):
                    c_el = ET.SubElement(row_el, f"{{{MAIN_NS}}}c", r=ref, s=style_id)
                    v_el = ET.SubElement(c_el, f"{{{MAIN_NS}}}v")
                    v_el.text = str(val).strip()
                else:
                    sidx = intern_str(sval)
                    c_el = ET.SubElement(row_el, f"{{{MAIN_NS}}}c", r=ref, s=style_id, t="s")
                    v_el = ET.SubElement(c_el, f"{{{MAIN_NS}}}v")
                    v_el.text = str(sidx)

        sheet_xml_bytes.append((sname, serialize_xml(ws)))
        summary_sheets.append({"name": sname, "rows": len(rows), "headers": headers})

    # [Content_Types].xml
    ET.register_namespace("", CT_NS)
    ct_root = ET.Element(f"{{{CT_NS}}}Types")
    ET.SubElement(ct_root, f"{{{CT_NS}}}Default", Extension="rels", ContentType="application/vnd.openxmlformats-package.relationships+xml")
    ET.SubElement(ct_root, f"{{{CT_NS}}}Default", Extension="xml", ContentType="application/xml")
    ET.SubElement(ct_root, f"{{{CT_NS}}}Override", PartName="/xl/workbook.xml", ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml")
    ET.SubElement(ct_root, f"{{{CT_NS}}}Override", PartName="/xl/styles.xml", ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml")
    ET.SubElement(ct_root, f"{{{CT_NS}}}Override", PartName="/xl/sharedStrings.xml", ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml")
    for idx in range(1, len(sheet_xml_bytes) + 1):
        ET.SubElement(ct_root, f"{{{CT_NS}}}Override", PartName=f"/xl/worksheets/sheet{idx}.xml", ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml")
    ct_bytes = serialize_xml(ct_root)

    # _rels/.rels
    ET.register_namespace("", PKG_REL_NS)
    root_rels = ET.Element(f"{{{PKG_REL_NS}}}Relationships")
    ET.SubElement(
        root_rels,
        f"{{{PKG_REL_NS}}}Relationship",
        Id="rId1",
        Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument",
        Target="xl/workbook.xml",
    )
    root_rels_bytes = serialize_xml(root_rels)

    # xl/_rels/workbook.xml.rels
    ET.register_namespace("", PKG_REL_NS)
    wb_rels = ET.Element(f"{{{PKG_REL_NS}}}Relationships")
    for idx in range(1, len(sheet_xml_bytes) + 1):
        ET.SubElement(
            wb_rels,
            f"{{{PKG_REL_NS}}}Relationship",
            Id=f"rId{idx}",
            Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet",
            Target=f"worksheets/sheet{idx}.xml",
        )
    ET.SubElement(
        wb_rels,
        f"{{{PKG_REL_NS}}}Relationship",
        Id=f"rId{len(sheet_xml_bytes) + 1}",
        Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles",
        Target="styles.xml",
    )
    ET.SubElement(
        wb_rels,
        f"{{{PKG_REL_NS}}}Relationship",
        Id=f"rId{len(sheet_xml_bytes) + 2}",
        Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings",
        Target="sharedStrings.xml",
    )
    wb_rels_bytes = serialize_xml(wb_rels)

    # xl/workbook.xml
    ET.register_namespace("", MAIN_NS)
    ET.register_namespace("r", REL_NS)
    wb = ET.Element(f"{{{MAIN_NS}}}workbook")
    sheets_el = ET.SubElement(wb, f"{{{MAIN_NS}}}sheets")
    for idx, (sname, _) in enumerate(sheet_xml_bytes, start=1):
        ET.SubElement(
            sheets_el,
            f"{{{MAIN_NS}}}sheet",
            name=sname,
            sheetId=str(idx),
            **{f"{{{REL_NS}}}id": f"rId{idx}"},
        )
    wb_bytes = serialize_xml(wb)

    # xl/styles.xml (0=default, 1=header bold shaded, 2=bordered body)
    styles_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<fonts count="2">'
        '<font><sz val="11"/><name val="Arial"/></font>'
        '<font><b/><sz val="11"/><name val="Arial"/></font>'
        '</fonts>'
        '<fills count="3">'
        '<fill><patternFill patternType="none"/></fill>'
        '<fill><patternFill patternType="gray125"/></fill>'
        '<fill><patternFill patternType="solid"><fgColor rgb="FFD9E1F2"/></patternFill></fill>'
        '</fills>'
        '<borders count="2">'
        '<border><left/><right/><top/><bottom/><diagonal/></border>'
        '<border>'
        '<left style="thin"><color rgb="FFD0D7DE"/></left>'
        '<right style="thin"><color rgb="FFD0D7DE"/></right>'
        '<top style="thin"><color rgb="FFD0D7DE"/></top>'
        '<bottom style="thin"><color rgb="FFD0D7DE"/></bottom>'
        '<diagonal/>'
        '</border>'
        '</borders>'
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
        '<cellXfs count="3">'
        '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
        '<xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment vertical="center"/></xf>'
        '<xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1"><alignment vertical="center"/></xf>'
        '</cellXfs>'
        '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
        '</styleSheet>'
    ).encode("utf-8")

    # xl/sharedStrings.xml
    ET.register_namespace("", MAIN_NS)
    sst_el = ET.Element(
        f"{{{MAIN_NS}}}sst",
        count=str(len(shared_strings)),
        uniqueCount=str(len(shared_strings)),
    )
    for s in shared_strings:
        si = ET.SubElement(sst_el, f"{{{MAIN_NS}}}si")
        t_el = ET.SubElement(si, f"{{{MAIN_NS}}}t")
        t_el.text = s
        ensure_xml_space(t_el, s)
    sst_bytes = serialize_xml(sst_el)

    tmp_out = output_path.with_suffix(output_path.suffix + ".tmp")
    with zipfile.ZipFile(tmp_out, "w", compression=zipfile.ZIP_DEFLATED) as zout:
        zout.writestr("[Content_Types].xml", ct_bytes)
        zout.writestr("_rels/.rels", root_rels_bytes)
        zout.writestr("xl/workbook.xml", wb_bytes)
        zout.writestr("xl/_rels/workbook.xml.rels", wb_rels_bytes)
        zout.writestr("xl/styles.xml", styles_xml)
        zout.writestr("xl/sharedStrings.xml", sst_bytes)
        for idx, (_, sbytes) in enumerate(sheet_xml_bytes, start=1):
            zout.writestr(f"xl/worksheets/sheet{idx}.xml", sbytes)
    os.replace(tmp_out, output_path)
    return {"output_path": str(output_path), "sheets": summary_sheets}


def edit_xlsx_file(
    source_path: Path,
    output_path: Path,
    *,
    sheet_name: str | None = None,
    updates: Sequence[dict[str, Any]] = (),
    append_rows: Sequence[Sequence[Any]] = (),
) -> dict[str, Any]:
    """Update specific cells (e.g. {'cell': 'D2', 'value': '=B2*C2'}) and/or append rows on an existing .xlsx."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(source_path, "r") as zin:
        names = zin.namelist()
        sst_root, sst_raw, shared_strings = _load_shared_strings(zin)
        sst_cache = {s: i for i, s in enumerate(shared_strings)}
        entries = _get_sheet_entries(zin)
        if not entries:
            raise ValueError(f"No worksheets found in {source_path}")
        target = entries[0]
        if sheet_name:
            matched = [e for e in entries if e[0] == sheet_name]
            if not matched:
                raise ValueError(f"Sheet '{sheet_name}' not found")
            target = matched[0]

        s_raw = zin.read(target[1])
        s_root = parse_xml(s_raw)
        ns_prefix = f"{{{MAIN_NS}}}" if "}" in s_root.tag else ""

        sheet_data = None
        for ch in s_root:
            if local_name(ch.tag) == "sheetData":
                sheet_data = ch
                break
        if sheet_data is None:
            sheet_data = ET.SubElement(s_root, f"{ns_prefix}sheetData")

        row_map: dict[int, ET.Element] = {}
        cell_elems: dict[str, ET.Element] = {}
        max_row_num = 0
        for r_el in iter_children_by_local(sheet_data, "row"):
            r_num = int(r_el.attrib.get("r", "0") or "0")
            if r_num > max_row_num:
                max_row_num = r_num
            row_map[r_num] = r_el
            for c_el in iter_children_by_local(r_el, "c"):
                ref = c_el.attrib.get("r", "")
                if ref:
                    cell_elems[ref.upper()] = c_el

        def set_cell(ref_str: str, val: Any) -> None:
            parsed = parse_cell_ref(ref_str)
            if not parsed:
                raise ValueError(f"Invalid cell reference: {ref_str}")
            r_num = parsed[0] + 1
            ref_up = ref_str.strip().upper()
            r_el = row_map.get(r_num)
            if r_el is None:
                r_el = ET.SubElement(sheet_data, f"{ns_prefix}row", r=str(r_num))
                row_map[r_num] = r_el
            c_el = cell_elems.get(ref_up)
            if c_el is None:
                c_el = ET.SubElement(r_el, f"{ns_prefix}c", r=ref_up)
                cell_elems[ref_up] = c_el

            for ch in list(c_el):
                if local_name(ch.tag) in ("f", "v", "is"):
                    c_el.remove(ch)

            if val is None or val == "":
                if "t" in c_el.attrib:
                    del c_el.attrib["t"]
                return
            sval = str(val)
            if sval.startswith("=") and len(sval) > 1:
                if "t" in c_el.attrib:
                    del c_el.attrib["t"]
                f_el = ET.SubElement(c_el, f"{ns_prefix}f")
                f_el.text = sval[1:]
            elif _is_number(val):
                if "t" in c_el.attrib:
                    del c_el.attrib["t"]
                v_el = ET.SubElement(c_el, f"{ns_prefix}v")
                v_el.text = sval.strip()
            else:
                _set_cell_string_value(c_el, sval, sst_root, shared_strings, sst_cache)

        updated_count = 0
        for u in updates:
            set_cell(str(u["cell"]), u.get("value"))
            updated_count += 1

        appended_count = 0
        cur_row = max_row_num
        for row_vals in append_rows:
            cur_row += 1
            for c_idx, val in enumerate(row_vals):
                ref = f"{idx_to_col_letters(c_idx)}{cur_row}"
                set_cell(ref, val)
            appended_count += 1

        # Keep <row> and <c> elements sorted in OOXML order so Excel never complains.
        def _row_sort_key(el: ET.Element) -> int:
            r_attr = el.attrib.get("r", "0")
            return int(r_attr) if r_attr.isdigit() else 10**9

        def _cell_sort_key(el: ET.Element) -> int:
            parsed = parse_cell_ref(el.attrib.get("r", ""))
            return parsed[1] if parsed else 10**9

        rows_in_sheet = [ch for ch in list(sheet_data) if local_name(ch.tag) == "row"]
        other_children = [ch for ch in list(sheet_data) if local_name(ch.tag) != "row"]
        for ch in list(sheet_data):
            sheet_data.remove(ch)
        for ch in other_children:
            sheet_data.append(ch)
        for r_el in sorted(rows_in_sheet, key=_row_sort_key):
            c_list = [ch for ch in list(r_el) if local_name(ch.tag) == "c"]
            non_c = [ch for ch in list(r_el) if local_name(ch.tag) != "c"]
            for ch in list(r_el):
                r_el.remove(ch)
            for ch in non_c:
                r_el.append(ch)
            for c_el in sorted(c_list, key=_cell_sort_key):
                r_el.append(c_el)
            sheet_data.append(r_el)

        modified: dict[str, bytes] = {target[1]: serialize_xml(s_root, s_raw)}
        if sst_root is not None:
            sst_root.set("count", str(len(shared_strings)))
            sst_root.set("uniqueCount", str(len(shared_strings)))
            modified["xl/sharedStrings.xml"] = serialize_xml(sst_root, sst_raw)

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
        "sheet": target[0],
        "updated_cells": updated_count,
        "appended_rows": appended_count,
    }
