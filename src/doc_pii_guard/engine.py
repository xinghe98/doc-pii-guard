"""High-level orchestration engine for masking, working on masked docs, restoring, and auditing."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Sequence

from .csv_proc import inspect_csv, mask_csv_file, read_csv_rows, restore_csv_file, write_csv_rows
from .docx_proc import create_docx_file, edit_docx_file, inspect_docx, mask_docx_file, restore_docx_file
from .pii import DEFAULT_CATEGORIES, find_pii_spans
from .table_ops import join_tables, query_table
from .vault import MASKED_DIR_NAME, PIIVault, is_registered_masked_path, register_masked_file
from .xlsx_proc import (
    create_xlsx_file,
    edit_xlsx_file,
    inspect_xlsx,
    mask_xlsx_file,
    read_xlsx_sheet_table,
    restore_xlsx_file,
)
from .xml_utils import parse_xml

SPREADSHEET_EXTS = {".xlsx", ".xlsm", ".csv", ".tsv", ".xls"}
WORD_EXTS = {".docx", ".doc"}
SUPPORTED_EXTS = SPREADSHEET_EXTS | WORD_EXTS


def _assert_masked_readable(path: Path) -> None:
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    if not is_registered_masked_path(path):
        raise PermissionError(
            f"Refused direct read/operation on unmasked path '{path}'. "
            "Call prepare_masked_copy first and operate only on the .pii_masked/ working copy."
        )


def _convert_xls_to_xlsx(xls_path: Path, out_xlsx: Path) -> None:
    soffice = shutil.which("soffice") or shutil.which("libreoffice")
    if not soffice:
        raise RuntimeError(
            f"Legacy binary .xls '{xls_path.name}' requires LibreOffice ('soffice') or saving as .xlsx first."
        )
    res = subprocess.run(
        [soffice, "--headless", "--convert-to", "xlsx", "--outdir", str(out_xlsx.parent), str(xls_path)],
        capture_output=True,
        text=True,
    )
    converted = out_xlsx.parent / f"{xls_path.stem}.xlsx"
    if res.returncode != 0 or not converted.exists():
        raise RuntimeError(f"Failed converting .xls to .xlsx: {res.stderr.strip()}")
    if converted != out_xlsx:
        os.replace(converted, out_xlsx)


def _default_masked_path(source_path: Path, output_dir: Path | None) -> Path:
    ext = source_path.suffix.lower()
    if ext == ".doc":
        ext = ".docx"
    elif ext == ".xls":
        ext = ".xlsx"
    base_dir = output_dir.resolve() if output_dir else (source_path.resolve().parent / MASKED_DIR_NAME)
    base_dir.mkdir(parents=True, exist_ok=True)
    stem = source_path.stem
    if not stem.endswith(".masked"):
        stem = f"{stem}.masked"
    return base_dir / f"{stem}{ext}"


def _mask_single_file(
    src: Path,
    dst: Path,
    vault: PIIVault,
    *,
    extra_name_columns: Sequence[str],
    extra_names: Sequence[str],
    exclude_words: Sequence[str],
    categories: Sequence[str],
) -> tuple[str, dict[str, Any]]:
    ext = src.suffix.lower()
    if ext in (".csv", ".tsv"):
        info = mask_csv_file(
            src,
            dst,
            vault,
            extra_name_columns=extra_name_columns,
            extra_names=extra_names,
            exclude_words=exclude_words,
            categories=categories,
        )
        return ext.lstrip("."), info
    if ext in (".xlsx", ".xlsm"):
        info = mask_xlsx_file(
            src,
            dst,
            vault,
            extra_name_columns=extra_name_columns,
            extra_names=extra_names,
            exclude_words=exclude_words,
            categories=categories,
        )
        return ext.lstrip("."), info
    if ext == ".xls":
        with tempfile.TemporaryDirectory(prefix="xls_conv_") as tmpd:
            tmp_xlsx = Path(tmpd) / f"{src.stem}.xlsx"
            _convert_xls_to_xlsx(src, tmp_xlsx)
            info = mask_xlsx_file(
                tmp_xlsx,
                dst,
                vault,
                extra_name_columns=extra_name_columns,
                extra_names=extra_names,
                exclude_words=exclude_words,
                categories=categories,
            )
            return "xlsx", info
    if ext in (".docx", ".doc"):
        info = mask_docx_file(
            src,
            dst,
            vault,
            extra_names=extra_names,
            exclude_words=exclude_words,
            categories=categories,
        )
        return "docx", info
    raise ValueError(f"Unsupported document extension: {src.suffix}")


def prepare_masked_copy(
    source_paths: str | Sequence[str],
    *,
    vault_id: str | None = None,
    output_dir: str | None = None,
    extra_name_columns: Sequence[str] = (),
    extra_names: Sequence[str] = (),
    exclude_words: Sequence[str] = (),
    categories: Sequence[str] = DEFAULT_CATEGORIES,
) -> dict[str, Any]:
    """Mask one or multiple spreadsheets/Word docs into `.pii_masked/` sharing a single vault."""
    raw_list = [source_paths] if isinstance(source_paths, str) else list(source_paths)
    if not raw_list:
        raise ValueError("source_paths cannot be empty")

    paths = [Path(p).expanduser().resolve() for p in raw_list]
    for p in paths:
        if not p.exists():
            raise FileNotFoundError(f"Source document not found: {p}")
        if p.suffix.lower() not in SUPPORTED_EXTS:
            raise ValueError(f"Unsupported file format '{p.suffix}' for {p.name}")

    vault = PIIVault.load_or_create(vault_id)
    out_dir = Path(output_dir).expanduser().resolve() if output_dir else None

    # Sort spreadsheets before Word docs so column-detected names propagate to Word prose.
    ordered = sorted(paths, key=lambda p: (0 if p.suffix.lower() in SPREADSHEET_EXTS else 1))
    results_by_src: dict[Path, dict[str, Any]] = {}
    masked_paths_order: list[tuple[Path, Path]] = []
    initial_known_count = len(vault.known_names)

    for src in ordered:
        dst = _default_masked_path(src, out_dir)
        fmt, info = _mask_single_file(
            src,
            dst,
            vault,
            extra_name_columns=extra_name_columns,
            extra_names=extra_names,
            exclude_words=exclude_words,
            categories=categories,
        )
        register_masked_file(dst, src, vault.vault_id)
        vault.record_file(src, dst, fmt, {"summary": info})
        results_by_src[src] = {
            "source_path": str(src),
            "masked_path": str(dst),
            "format": fmt,
            **info,
        }
        masked_paths_order.append((src, dst))

    # If later files discovered additional names, propagate across earlier masked files in the batch.
    if len(masked_paths_order) > 1 and len(vault.known_names) > initial_known_count:
        for src, dst in masked_paths_order[:-1]:
            _, extra_info = _mask_single_file(
                dst,
                dst,
                vault,
                extra_name_columns=extra_name_columns,
                extra_names=extra_names,
                exclude_words=exclude_words,
                categories=categories,
            )
            extra_counts = extra_info.get("pii_counts", {})
            if extra_counts:
                cur_counts = results_by_src[src].setdefault("pii_counts", {})
                for k, v in extra_counts.items():
                    cur_counts[k] = cur_counts.get(k, 0) + v

    vault.save()
    ordered_results = [results_by_src[p] for p in paths]
    return {
        "vault_id": vault.vault_id,
        "files": ordered_results,
        "total_tokens_in_vault": len(vault.reverse),
    }


def restore_document(
    masked_path: str,
    output_path: str,
    vault_id: str,
    *,
    irreversible_style: str | None = None,
) -> dict[str, Any]:
    """Restore tokens in a masked working file back to real PII (or irreversible redaction)."""
    m_path = Path(masked_path).expanduser().resolve()
    o_path = Path(output_path).expanduser().resolve()
    if not m_path.exists():
        raise FileNotFoundError(f"Masked file not found: {m_path}")
    if irreversible_style is None and MASKED_DIR_NAME in o_path.parts:
        raise ValueError(
            f"Refused restoring real PII inside '{MASKED_DIR_NAME}/'. "
            "Choose an output_path outside .pii_masked/ so masked working directory stays PII-free."
        )

    vault = PIIVault.load(vault_id)
    ext = m_path.suffix.lower()
    if ext in (".csv", ".tsv"):
        return restore_csv_file(m_path, o_path, vault, irreversible_style=irreversible_style)
    if ext in (".xlsx", ".xlsm"):
        return restore_xlsx_file(m_path, o_path, vault, irreversible_style=irreversible_style)
    if ext == ".docx":
        return restore_docx_file(m_path, o_path, vault, irreversible_style=irreversible_style)
    raise ValueError(f"Unsupported format for restoration: {m_path.suffix}")


def export_redacted(
    input_path: str,
    output_path: str,
    *,
    vault_id: str | None = None,
    style: str = "standard",
    extra_name_columns: Sequence[str] = (),
    extra_names: Sequence[str] = (),
    exclude_words: Sequence[str] = (),
    categories: Sequence[str] = DEFAULT_CATEGORIES,
) -> dict[str, Any]:
    """Export an irreversibly redacted copy (e.g. 张* / 138****5678) for sharing."""
    in_path = Path(input_path).expanduser().resolve()
    out_path = Path(output_path).expanduser().resolve()
    if not in_path.exists():
        raise FileNotFoundError(f"Input file not found: {in_path}")

    if vault_id:
        return restore_document(
            str(in_path),
            str(out_path),
            vault_id,
            irreversible_style=style,
        )

    # Mask into a temp file with ephemeral vault, then redact tokens directly into out_path.
    with tempfile.TemporaryDirectory(prefix="pii_redact_") as tmpd:
        ephem_vault = PIIVault(vault_id="ephemeral_redact")
        ext = in_path.suffix.lower()
        target_ext = ".docx" if ext == ".doc" else (".xlsx" if ext == ".xls" else ext)
        tmp_masked = Path(tmpd) / f"staged.masked{target_ext}"
        _mask_single_file(
            in_path,
            tmp_masked,
            ephem_vault,
            extra_name_columns=extra_name_columns,
            extra_names=extra_names,
            exclude_words=exclude_words,
            categories=categories,
        )
        if target_ext in (".csv", ".tsv"):
            return restore_csv_file(tmp_masked, out_path, ephem_vault, irreversible_style=style)
        if target_ext in (".xlsx", ".xlsm"):
            return restore_xlsx_file(tmp_masked, out_path, ephem_vault, irreversible_style=style)
        if target_ext == ".docx":
            return restore_docx_file(tmp_masked, out_path, ephem_vault, irreversible_style=style)
        raise ValueError(f"Unsupported file format: {in_path.suffix}")


def inspect_masked_document(
    masked_path: str,
    *,
    sheet_name: str | None = None,
    row_start: int = 1,
    row_end: int = 50,
) -> dict[str, Any]:
    p = Path(masked_path).expanduser().resolve()
    _assert_masked_readable(p)
    ext = p.suffix.lower()
    if ext in (".csv", ".tsv"):
        return inspect_csv(p, row_start=row_start, row_end=row_end)
    if ext in (".xlsx", ".xlsm"):
        return inspect_xlsx(p, sheet_name=sheet_name, row_start=row_start, row_end=row_end)
    if ext == ".docx":
        return inspect_docx(p, paragraph_start=row_start, paragraph_end=row_end)
    raise ValueError(f"Unsupported format: {p.suffix}")


def _load_masked_table(path: Path, sheet_name: str | None = None) -> tuple[list[str], list[list[str]]]:
    _assert_masked_readable(path)
    ext = path.suffix.lower()
    if ext in (".csv", ".tsv"):
        info = inspect_csv(path, row_start=1, row_end=1)
        rows, _, _ = read_csv_rows(path)
        hdr_idx = info["header_row"] - 1
        headers = rows[hdr_idx] if hdr_idx < len(rows) else []
        data_rows = rows[hdr_idx + 1 :]
        return headers, data_rows
    if ext in (".xlsx", ".xlsm"):
        _, headers, data_rows, _, _ = read_xlsx_sheet_table(path, sheet_name=sheet_name)
        return headers, data_rows
    raise ValueError(f"Tabular operation unsupported on {path.suffix}")


def _save_table(output_path: Path, headers: list[str], rows: list[list[str]], sheet_name: str = "Result") -> None:
    ext = output_path.suffix.lower()
    if ext in (".csv", ".tsv"):
        delim = "\t" if ext == ".tsv" else ","
        write_csv_rows(output_path, [headers, *rows], delimiter=delim)
    elif ext == ".xlsx":
        create_xlsx_file(output_path, [{"name": sheet_name, "headers": headers, "rows": rows}])
    else:
        raise ValueError(f"Output must be .xlsx, .csv, or .tsv (got {output_path.suffix})")


def query_masked_spreadsheet(
    masked_path: str,
    *,
    sheet_name: str | None = None,
    filters: list[dict[str, Any]] | None = None,
    select_columns: list[str] | None = None,
    sort_by: str | None = None,
    sort_desc: bool = False,
    group_by: list[str] | None = None,
    aggregations: list[dict[str, str]] | None = None,
    limit: int = 200,
    offset: int = 0,
    save_to_masked_path: str | None = None,
    output_sheet_name: str = "Result",
) -> dict[str, Any]:
    p = Path(masked_path).expanduser().resolve()
    headers, data_rows = _load_masked_table(p, sheet_name=sheet_name)

    if save_to_masked_path:
        # Save ALL matching rows when saving, then paginate preview for response.
        full_h, full_r, total = query_table(
            headers,
            data_rows,
            filters=filters,
            select_columns=select_columns,
            sort_by=sort_by,
            sort_desc=sort_desc,
            group_by=group_by,
            aggregations=aggregations,
            limit=0,
            offset=0,
        )
        out_p = Path(save_to_masked_path).expanduser().resolve()
        if not is_registered_masked_path(out_p):
            raise PermissionError("save_to_masked_path must be inside .pii_masked/ directory")
        _save_table(out_p, full_h, full_r, sheet_name=output_sheet_name)
        preview = full_r[offset : offset + limit] if limit > 0 else full_r[offset:]
        return {
            "headers": full_h,
            "total_rows": total,
            "returned_rows": len(preview),
            "rows": preview,
            "saved_to": str(out_p),
        }

    out_h, out_r, total = query_table(
        headers,
        data_rows,
        filters=filters,
        select_columns=select_columns,
        sort_by=sort_by,
        sort_desc=sort_desc,
        group_by=group_by,
        aggregations=aggregations,
        limit=limit,
        offset=offset,
    )
    return {
        "headers": out_h,
        "total_rows": total,
        "returned_rows": len(out_r),
        "rows": out_r,
    }


def join_masked_spreadsheets(
    left_path: str,
    right_path: str,
    output_masked_path: str,
    *,
    left_on: str,
    right_on: str,
    how: str = "inner",
    left_sheet: str | None = None,
    right_sheet: str | None = None,
    output_sheet_name: str = "Merged",
    preview_limit: int = 30,
) -> dict[str, Any]:
    lp = Path(left_path).expanduser().resolve()
    rp = Path(right_path).expanduser().resolve()
    op = Path(output_masked_path).expanduser().resolve()
    if not is_registered_masked_path(op):
        raise PermissionError("output_masked_path must be inside .pii_masked/ directory")

    lh, lr = _load_masked_table(lp, sheet_name=left_sheet)
    rh, rr = _load_masked_table(rp, sheet_name=right_sheet)
    out_h, out_r = join_tables(lh, lr, rh, rr, left_on=left_on, right_on=right_on, how=how)
    _save_table(op, out_h, out_r, sheet_name=output_sheet_name)
    return {
        "output_masked_path": str(op),
        "headers": out_h,
        "total_rows": len(out_r),
        "preview_rows": out_r[:preview_limit],
    }


def create_masked_spreadsheet(
    output_masked_path: str,
    *,
    sheets: Sequence[dict[str, Any]],
    freeze_header: bool = True,
) -> dict[str, Any]:
    op = Path(output_masked_path).expanduser().resolve()
    if not is_registered_masked_path(op):
        raise PermissionError("output_masked_path must be inside .pii_masked/ directory")
    if op.suffix.lower() in (".csv", ".tsv"):
        if len(sheets) != 1:
            raise ValueError("CSV/TSV supports only 1 sheet")
        spec = sheets[0]
        rows_out = []
        if spec.get("headers"):
            rows_out.append([str(h) for h in spec["headers"]])
        for r in spec.get("rows", []):
            rows_out.append(["" if v is None else str(v) for v in r])
        delim = "\t" if op.suffix.lower() == ".tsv" else ","
        write_csv_rows(op, rows_out, delimiter=delim)
        return {"output_path": str(op), "rows": len(spec.get("rows", []))}
    return create_xlsx_file(op, sheets, freeze_header=freeze_header)


def edit_masked_spreadsheet(
    masked_path: str,
    output_masked_path: str,
    *,
    sheet_name: str | None = None,
    updates: Sequence[dict[str, Any]] = (),
    append_rows: Sequence[Sequence[Any]] = (),
) -> dict[str, Any]:
    mp = Path(masked_path).expanduser().resolve()
    op = Path(output_masked_path).expanduser().resolve()
    _assert_masked_readable(mp)
    if not is_registered_masked_path(op):
        raise PermissionError("output_masked_path must be inside .pii_masked/ directory")
    if mp.suffix.lower() in (".csv", ".tsv"):
        rows, delim, _ = read_csv_rows(mp)
        for u in updates:
            # Support {'row': 1-based, 'col': 1-based, 'value': ...} or {'cell': 'B2', ...}
            if "cell" in u:
                from .xlsx_proc import parse_cell_ref

                parsed = parse_cell_ref(str(u["cell"]))
                if not parsed:
                    raise ValueError(f"Invalid cell ref: {u['cell']}")
                r_idx, c_idx = parsed
            else:
                r_idx = int(u["row"]) - 1
                c_idx = int(u["col"]) - 1
            while len(rows) <= r_idx:
                rows.append([])
            while len(rows[r_idx]) <= c_idx:
                rows[r_idx].append("")
            rows[r_idx][c_idx] = "" if u.get("value") is None else str(u["value"])
        for r in append_rows:
            rows.append(["" if v is None else str(v) for v in r])
        write_csv_rows(op, rows, delimiter=delim)
        return {"output_path": str(op), "updated_cells": len(updates), "appended_rows": len(append_rows)}
    return edit_xlsx_file(mp, op, sheet_name=sheet_name, updates=updates, append_rows=append_rows)


def edit_masked_docx(
    masked_path: str,
    output_masked_path: str,
    *,
    replacements: Sequence[dict[str, str]] = (),
    table_updates: Sequence[dict[str, Any]] = (),
    append_paragraphs: Sequence[str] = (),
    append_table: dict[str, Any] | None = None,
) -> dict[str, Any]:
    mp = Path(masked_path).expanduser().resolve()
    op = Path(output_masked_path).expanduser().resolve()
    _assert_masked_readable(mp)
    if not is_registered_masked_path(op):
        raise PermissionError("output_masked_path must be inside .pii_masked/ directory")
    return edit_docx_file(
        mp,
        op,
        replacements=replacements,
        table_updates=table_updates,
        append_paragraphs=append_paragraphs,
        append_table=append_table,
    )


def create_masked_docx(
    output_masked_path: str,
    *,
    title: str | None = None,
    blocks: Sequence[dict[str, Any]] = (),
) -> dict[str, Any]:
    op = Path(output_masked_path).expanduser().resolve()
    if not is_registered_masked_path(op):
        raise PermissionError("output_masked_path must be inside .pii_masked/ directory")
    return create_docx_file(op, title=title, blocks=blocks)


def audit_document(file_path: str, *, vault_id: str | None = None) -> dict[str, Any]:
    """Audit a file locally for unmasked PII without ever returning raw PII strings."""
    p = Path(file_path).expanduser().resolve()
    if not p.exists():
        raise FileNotFoundError(f"File not found: {p}")

    known_names: list[str] = []
    vault_raws: list[tuple[str, str]] = []
    if vault_id:
        v = PIIVault.load(vault_id)
        known_names = list(v.known_names)
        vault_raws = v.all_raw_values()

    counts: dict[str, int] = {}
    locations: list[str] = []

    def check_text(loc: str, txt: str) -> None:
        if not txt or not txt.strip():
            return
        spans = find_pii_spans(txt, known_names=known_names)
        for sp in spans:
            counts[sp.category] = counts.get(sp.category, 0) + 1
            if len(locations) < 25:
                locations.append(f"{loc} ({sp.category})")
        if not spans and vault_raws:
            for cat, raw in vault_raws:
                if len(raw) >= 2 and raw in txt:
                    counts[cat] = counts.get(cat, 0) + 1
                    if len(locations) < 25:
                        locations.append(f"{loc} ({cat})")
                    break

    ext = p.suffix.lower()
    if ext in (".csv", ".tsv"):
        rows, _, _ = read_csv_rows(p)
        for r_i, row in enumerate(rows, start=1):
            for c_i, cell in enumerate(row, start=1):
                check_text(f"row {r_i} col {c_i}", cell)
    elif ext in (".xlsx", ".xlsm"):
        with zipfile.ZipFile(p, "r") as zf:
            from .xlsx_proc import _get_sheet_entries, _load_shared_strings, _sheet_to_grid

            _, _, sst = _load_shared_strings(zf)
            for sname, spath in _get_sheet_entries(zf):
                sroot = parse_xml(zf.read(spath))
                grid, _ = _sheet_to_grid(sroot, sst)
                for r_i, row in enumerate(grid, start=1):
                    for c_i, cell in enumerate(row, start=1):
                        check_text(f"{sname}!R{r_i}C{c_i}", cell)
    elif ext == ".docx":
        info = inspect_docx(p, paragraph_start=1, paragraph_end=100000)
        for idx, para in enumerate(info["paragraphs"], start=1):
            check_text(f"paragraph {idx}", para["text"])
        for t_i, tbl in enumerate(info["tables"], start=1):
            for r_i, row in enumerate(tbl, start=1):
                for c_i, cell in enumerate(row, start=1):
                    check_text(f"table {t_i} R{r_i}C{c_i}", cell)
        for hf_name, lines in info["headers_footers"].items():
            for l_i, line in enumerate(lines, start=1):
                check_text(f"{hf_name} line {l_i}", line)
    else:
        txt = p.read_text(encoding="utf-8", errors="ignore")
        for l_i, line in enumerate(txt.splitlines(), start=1):
            check_text(f"line {l_i}", line)

    total = sum(counts.values())
    return {
        "file_path": str(p),
        "clean": total == 0,
        "total_findings": total,
        "counts_by_category": counts,
        "sample_locations": locations,
    }
