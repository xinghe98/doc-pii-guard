"""Shared tabular operations (header classification, filtering, sorting, grouping, joining)."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Sequence

from .pii import classify_header


def detect_header_row(rows: Sequence[Sequence[str]], max_scan: int = 12) -> tuple[int, dict[int, str]]:
    """Find the most likely header row index and map col_idx -> PII category.

    Returns (header_row_idx, {col_idx: pii_category}).
    """
    if not rows:
        return 0, {}
    limit = min(len(rows), max_scan)
    best_row = 0
    best_score = -1
    best_cats: dict[int, str] = {}

    for r_idx in range(limit):
        row = rows[r_idx]
        non_empty = [c for c in row if str(c).strip()]
        if not non_empty:
            continue
        cats: dict[int, str] = {}
        for c_idx, val in enumerate(row):
            cat = classify_header(str(val))
            if cat:
                cats[c_idx] = cat
        # Prefer rows with PII headers, breaking ties by number of distinct non-empty headers.
        score = len(cats) * 100 + min(len(non_empty), 50)
        if len(cats) > 0 and score > best_score:
            best_score = score
            best_row = r_idx
            best_cats = cats

    if best_score < 0:
        # Fallback: first non-empty row with >=2 cells.
        for r_idx in range(limit):
            if sum(1 for c in rows[r_idx] if str(c).strip()) >= 2:
                return r_idx, {}
        return 0, {}
    return best_row, best_cats


def _try_float(val: Any) -> float | None:
    if isinstance(val, (int, float)) and not isinstance(val, bool):
        return float(val)
    s = str(val).strip().replace(",", "")
    if not s:
        return None
    try:
        return float(s)
    except ValueError:
        return None


def _compare(cell: str, op: str, target: Any) -> bool:
    s = str(cell)
    if op == "contains":
        return str(target).lower() in s.lower()
    if op == "not_contains":
        return str(target).lower() not in s.lower()
    if op == "in":
        targets = target if isinstance(target, (list, tuple, set)) else [target]
        return s in [str(t) for t in targets]
    if op == "regex":
        return bool(re.search(str(target), s))

    num_c = _try_float(s)
    num_t = _try_float(target)
    if num_c is not None and num_t is not None:
        left, right = num_c, num_t
    else:
        left, right = s, str(target)

    if op in ("==", "eq"):
        return left == right
    if op in ("!=", "ne"):
        return left != right
    if op in (">", "gt"):
        return left > right
    if op in (">=", "ge", "gte"):
        return left >= right
    if op in ("<", "lt"):
        return left < right
    if op in ("<=", "le", "lte"):
        return left <= right
    raise ValueError(f"Unsupported filter operator: {op}")


def deduplicate_headers(headers: Sequence[str]) -> list[str]:
    """Ensure header names are non-empty and unique while preserving order."""
    seen: dict[str, int] = {}
    out: list[str] = []
    for idx, h in enumerate(headers):
        base = str(h).strip() or f"col_{idx + 1}"
        count = seen.get(base, 0) + 1
        seen[base] = count
        out.append(base if count == 1 else f"{base}_{count}")
    return out


def query_table(
    headers: list[str],
    rows: list[list[str]],
    *,
    filters: list[dict[str, Any]] | None = None,
    select_columns: list[str] | None = None,
    sort_by: str | None = None,
    sort_desc: bool = False,
    group_by: list[str] | None = None,
    aggregations: list[dict[str, str]] | None = None,
    limit: int = 200,
    offset: int = 0,
) -> tuple[list[str], list[list[str]], int]:
    """Filter, group/aggregate, sort, project, and paginate tabular data.

    Returns (result_headers, result_rows, total_matching_rows).
    """
    unique_headers = deduplicate_headers(headers)
    col_index = {h: i for i, h in enumerate(unique_headers)}
    filtered = rows
    if filters:
        next_rows: list[list[str]] = []
        for row in filtered:
            ok = True
            for cond in filters:
                col = cond["column"]
                if col not in col_index:
                    raise ValueError(f"Column not found in filter: {col}")
                idx = col_index[col]
                val = row[idx] if idx < len(row) else ""
                if not _compare(val, cond.get("op", "=="), cond.get("value", "")):
                    ok = False
                    break
            if ok:
                next_rows.append(row)
        filtered = next_rows

    out_headers = list(headers)
    out_rows = [list(r) + [""] * max(0, len(headers) - len(r)) for r in filtered]

    if group_by or aggregations:
        gb_cols = group_by or []
        for col in gb_cols:
            if col not in col_index:
                raise ValueError(f"Column not found in group_by: {col}")
        aggs = aggregations or [{"column": "*", "func": "count", "alias": "count"}]
        groups: dict[tuple[str, ...], list[list[str]]] = defaultdict(list)
        for r in out_rows:
            key = tuple(r[col_index[c]] for c in gb_cols)
            groups[key].append(r)

        agg_headers = list(gb_cols)
        for a in aggs:
            alias = a.get("alias") or f"{a['func']}({a.get('column', '*')})"
            agg_headers.append(alias)

        agg_rows: list[list[str]] = []
        for key, grp_rows in groups.items():
            row_out = list(key)
            for a in aggs:
                func = a["func"].lower()
                col = a.get("column", "*")
                if func == "count" and col == "*":
                    row_out.append(str(len(grp_rows)))
                    continue
                if col not in col_index:
                    raise ValueError(f"Column not found in aggregation: {col}")
                cidx = col_index[col]
                raw_vals = [r[cidx] for r in grp_rows if r[cidx].strip() != ""]
                if func == "count":
                    row_out.append(str(len(raw_vals)))
                elif func == "count_distinct":
                    row_out.append(str(len(set(raw_vals))))
                else:
                    nums = [n for v in raw_vals if (n := _try_float(v)) is not None]
                    if not nums:
                        row_out.append("")
                    elif func == "sum":
                        val = sum(nums)
                        row_out.append(str(int(val)) if val.is_integer() else f"{val:.4f}".rstrip("0").rstrip("."))
                    elif func in ("avg", "mean"):
                        val = sum(nums) / len(nums)
                        row_out.append(f"{val:.4f}".rstrip("0").rstrip("."))
                    elif func == "min":
                        val = min(nums)
                        row_out.append(str(int(val)) if val.is_integer() else str(val))
                    elif func == "max":
                        val = max(nums)
                        row_out.append(str(int(val)) if val.is_integer() else str(val))
                    else:
                        raise ValueError(f"Unsupported aggregation func: {func}")
            agg_rows.append(row_out)

        out_headers = agg_headers
        out_rows = agg_rows
        col_index = {h: i for i, h in enumerate(out_headers)}

    if sort_by:
        if sort_by not in col_index:
            raise ValueError(f"Column not found in sort_by: {sort_by}")
        s_idx = col_index[sort_by]

        def _sort_key(r: list[str]) -> tuple[int, Any]:
            val = r[s_idx] if s_idx < len(r) else ""
            num = _try_float(val)
            if num is not None:
                return (0, num)
            return (1, val)

        out_rows.sort(key=_sort_key, reverse=sort_desc)

    if select_columns:
        idxs = []
        for c in select_columns:
            if c not in col_index:
                raise ValueError(f"Column not found in select_columns: {c}")
            idxs.append(col_index[c])
        out_headers = list(select_columns)
        out_rows = [[r[i] for i in idxs] for r in out_rows]

    total = len(out_rows)
    sliced = out_rows[offset : offset + limit] if limit > 0 else out_rows[offset:]
    return out_headers, sliced, total


def join_tables(
    left_headers: list[str],
    left_rows: list[list[str]],
    right_headers: list[str],
    right_rows: list[list[str]],
    *,
    left_on: str,
    right_on: str,
    how: str = "inner",
    right_suffix: str = "_right",
) -> tuple[list[str], list[list[str]]]:
    """Join two tables on `left_on` == `right_on`."""
    if left_on not in left_headers:
        raise ValueError(f"Column '{left_on}' not found in left table")
    if right_on not in right_headers:
        raise ValueError(f"Column '{right_on}' not found in right table")
    how_low = how.lower()
    if how_low not in {"inner", "left", "right", "outer"}:
        raise ValueError(f"Unsupported join type: {how}")

    l_idx = left_headers.index(left_on)
    r_idx = right_headers.index(right_on)

    # Disambiguate colliding right column names (excluding right_on in inner/left when redundant? Keep all or suffix collisions).
    left_set = set(left_headers)
    r_keep_indices = [i for i, h in enumerate(right_headers) if not (i == r_idx and h == left_on and how_low in ("inner", "left"))]
    out_headers = list(left_headers)
    for i in r_keep_indices:
        h = right_headers[i]
        out_headers.append(f"{h}{right_suffix}" if h in left_set else h)

    r_lookup: dict[str, list[list[str]]] = defaultdict(list)
    for row in right_rows:
        padded = list(row) + [""] * max(0, len(right_headers) - len(row))
        key = padded[r_idx].strip()
        r_lookup[key].append(padded)

    matched_right_keys: set[str] = set()
    out_rows: list[list[str]] = []

    for l_row in left_rows:
        l_pad = list(l_row) + [""] * max(0, len(left_headers) - len(l_row))
        key = l_pad[l_idx].strip()
        matches = r_lookup.get(key) if key else None
        if matches:
            matched_right_keys.add(key)
            for r_pad in matches:
                out_rows.append(l_pad + [r_pad[i] for i in r_keep_indices])
        elif how_low in ("left", "outer"):
            out_rows.append(l_pad + [""] * len(r_keep_indices))

    if how_low in ("right", "outer"):
        for r_row in right_rows:
            r_pad = list(r_row) + [""] * max(0, len(right_headers) - len(r_row))
            key = r_pad[r_idx].strip()
            if key not in matched_right_keys:
                left_blank = [""] * len(left_headers)
                if left_on == right_on:
                    left_blank[l_idx] = r_pad[r_idx]
                out_rows.append(left_blank + [r_pad[i] for i in r_keep_indices])

    return out_headers, out_rows
