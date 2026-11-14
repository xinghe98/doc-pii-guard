"""CSV / TSV encoding-aware PII masking, restoration, inspection, and writing."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Sequence

from .pii import DEFAULT_CATEGORIES, apply_replacements, find_pii_spans
from .table_ops import detect_header_row
from .vault import PIIVault


def detect_encoding_and_read(path: Path) -> tuple[str, str]:
    raw_bytes = path.read_bytes()
    for enc in ("utf-8-sig", "utf-8", "gb18030", "gbk", "utf-16"):
        try:
            return raw_bytes.decode(enc), enc
        except UnicodeDecodeError:
            continue
    return raw_bytes.decode("latin-1"), "latin-1"


def detect_delimiter(text: str, path: Path) -> str:
    if path.suffix.lower() == ".tsv":
        return "\t"
    sample = "\n".join(text.splitlines()[:20])
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",\t;|")
        return dialect.delimiter
    except csv.Error:
        return ","


def read_csv_rows(path: Path) -> tuple[list[list[str]], str, str]:
    text, encoding = detect_encoding_and_read(path)
    delimiter = detect_delimiter(text, path)
    rows = list(csv.reader(text.splitlines(), delimiter=delimiter))
    return rows, delimiter, encoding


def write_csv_rows(path: Path, rows: Sequence[Sequence[str]], delimiter: str = ",", encoding: str = "utf-8-sig") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding=encoding, newline="") as f:
        writer = csv.writer(f, delimiter=delimiter)
        for row in rows:
            writer.writerow(row)


def mask_csv_file(
    source_path: Path,
    masked_path: Path,
    vault: PIIVault,
    *,
    extra_name_columns: Sequence[str] = (),
    extra_names: Sequence[str] = (),
    exclude_words: Sequence[str] = (),
    categories: Sequence[str] = DEFAULT_CATEGORIES,
) -> dict[str, Any]:
    rows, delimiter, orig_encoding = read_csv_rows(source_path)
    if not rows:
        write_csv_rows(masked_path, [], delimiter=delimiter, encoding="utf-8-sig")
        return {"rows": 0, "cols": 0, "header_row": 0, "pii_counts": {}, "encoding": orig_encoding}

    hdr_idx, col_cats = detect_header_row(rows)
    # Apply user-specified extra_name_columns.
    if extra_name_columns and hdr_idx < len(rows):
        extra_set = {c.strip().lower() for c in extra_name_columns if c.strip()}
        for c_idx, cell in enumerate(rows[hdr_idx]):
            if cell.strip().lower() in extra_set:
                col_cats[c_idx] = "NAME"

    counts: dict[str, int] = {}

    def alloc(cat: str, canon: str, raw: str) -> str:
        tok = vault.get_or_create_token(cat, canon, raw)
        counts[cat] = counts.get(cat, 0) + 1
        return tok

    # Pass 1: mask with column awareness + patterns (populates vault.known_names).
    pass1_rows: list[list[str]] = []
    for r_idx, row in enumerate(rows):
        new_row: list[str] = []
        for c_idx, cell in enumerate(row):
            if r_idx <= hdr_idx:
                # Header / banner row: still mask explicit phone/ID/email/known names if embedded in title.
                spans = find_pii_spans(
                    cell,
                    column_category=None,
                    known_names=vault.known_names,
                    extra_names=extra_names,
                    exclude_words=exclude_words,
                    categories=categories,
                )
            else:
                col_cat = col_cats.get(c_idx)
                hdr_label = rows[hdr_idx][c_idx].strip() if c_idx < len(rows[hdr_idx]) else ""
                if cell.strip() == hdr_label:
                    col_cat = None
                spans = find_pii_spans(
                    cell,
                    column_category=col_cat,
                    known_names=vault.known_names,
                    extra_names=extra_names,
                    exclude_words=exclude_words,
                    categories=categories,
                )
            masked_cell, _ = apply_replacements(cell, spans, alloc)
            new_row.append(masked_cell)
        pass1_rows.append(new_row)

    # Pass 2: cross-reference newly learned known_names in non-name columns / free text.
    final_rows: list[list[str]] = []
    for r_idx, row in enumerate(pass1_rows):
        new_row = []
        for cell in row:
            spans = find_pii_spans(
                cell,
                column_category=None,
                known_names=vault.known_names,
                extra_names=extra_names,
                exclude_words=exclude_words,
                categories=categories,
            )
            masked_cell, _ = apply_replacements(cell, spans, alloc)
            new_row.append(masked_cell)
        final_rows.append(new_row)

    write_csv_rows(masked_path, final_rows, delimiter=delimiter, encoding="utf-8-sig")
    headers = final_rows[hdr_idx] if hdr_idx < len(final_rows) else []
    max_cols = max((len(r) for r in final_rows), default=0)
    return {
        "rows": len(final_rows),
        "cols": max_cols,
        "header_row": hdr_idx + 1,
        "headers": headers,
        "pii_counts": counts,
        "encoding": orig_encoding,
        "delimiter": delimiter,
    }


def restore_csv_file(
    masked_path: Path,
    output_path: Path,
    vault: PIIVault,
    *,
    irreversible_style: str | None = None,
) -> dict[str, Any]:
    rows, delimiter, _ = read_csv_rows(masked_path)
    total_replaced = 0
    unresolved: set[str] = set()
    out_rows: list[list[str]] = []

    for row in rows:
        new_row: list[str] = []
        for cell in row:
            if irreversible_style:
                new_cell, cnt = vault.redact_text_tokens(cell, style=irreversible_style)
                total_replaced += cnt
            else:
                new_cell, cnt, unres = vault.restore_text(cell)
                total_replaced += cnt
                unresolved.update(unres)
            new_row.append(new_cell)
        out_rows.append(new_row)

    write_csv_rows(output_path, out_rows, delimiter=delimiter, encoding="utf-8-sig")
    return {
        "output_path": str(output_path),
        "restored_count": total_replaced,
        "unresolved_tokens": sorted(unresolved),
    }


def inspect_csv(path: Path, row_start: int = 1, row_end: int = 50) -> dict[str, Any]:
    rows, delimiter, encoding = read_csv_rows(path)
    hdr_idx, _ = detect_header_row(rows)
    total_rows = len(rows)
    start_idx = max(0, row_start - 1)
    end_idx = min(total_rows, row_end)
    return {
        "format": path.suffix.lstrip(".").lower(),
        "encoding": encoding,
        "delimiter": delimiter,
        "total_rows": total_rows,
        "total_cols": max((len(r) for r in rows), default=0),
        "header_row": hdr_idx + 1,
        "headers": rows[hdr_idx] if hdr_idx < len(rows) else [],
        "row_start": start_idx + 1,
        "row_end": end_idx,
        "rows": rows[start_idx:end_idx],
    }
