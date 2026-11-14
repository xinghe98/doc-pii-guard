"""Stdio MCP server exposing doc-pii-guard masking, spreadsheet/Word, and restoration tools."""

from __future__ import annotations

import json
import sys
import traceback
from typing import Any

from .engine import (
    audit_document,
    create_masked_docx,
    create_masked_spreadsheet,
    edit_masked_docx,
    edit_masked_spreadsheet,
    export_redacted,
    inspect_masked_document,
    join_masked_spreadsheets,
    prepare_masked_copy,
    query_masked_spreadsheet,
    restore_document,
)
from .pii import DEFAULT_CATEGORIES
from .vault import PIIVault

SUPPORTED_PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")

TOOLS: list[dict[str, Any]] = [
    {
        "name": "prepare_masked_copy",
        "description": (
            "Create reversible PII-masked working copies in .pii_masked/ for spreadsheets "
            "(.xlsx, .xlsm, .xls, .csv, .tsv) and Word documents (.docx, .doc). "
            "Masks names, ID card numbers, phone numbers, bank cards, and emails using consistent "
            "tokens (#PII_NAME_0001#, #PII_ID_0001#, etc.) without altering structure or formulas. "
            "Pass multiple paths together (or pass an existing vault_id) so cross-file joins share identical tokens."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "source_paths": {
                    "oneOf": [
                        {"type": "string"},
                        {"type": "array", "items": {"type": "string"}},
                    ],
                    "description": "Path or list of paths to original spreadsheet/Word files.",
                },
                "vault_id": {
                    "type": "string",
                    "description": "Optional existing vault_id to reuse consistent token mappings across batches.",
                },
                "output_dir": {
                    "type": "string",
                    "description": "Optional directory for masked working copies (defaults to <source_dir>/.pii_masked).",
                },
                "extra_name_columns": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Additional column header names to treat as personal NAME columns.",
                },
                "extra_names": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Explicit personal names to mask even when unlabeled in prose.",
                },
                "exclude_words": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Words that must never be masked as PII.",
                },
                "categories": {
                    "type": "array",
                    "items": {"type": "string", "enum": list(DEFAULT_CATEGORIES)},
                    "description": "Optional subset of PII categories to mask.",
                },
            },
            "required": ["source_paths"],
        },
    },
    {
        "name": "inspect_masked_document",
        "description": (
            "Inspect a masked working copy (.xlsx, .xlsm, .csv, .tsv, .docx). "
            "Returns sheet names, column headers, and paginated rows for spreadsheets, "
            "or paragraphs, tables, and headers/footers for Word documents."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "masked_path": {"type": "string"},
                "sheet_name": {"type": "string", "description": "Optional worksheet name for .xlsx/.xlsm."},
                "row_start": {"type": "integer", "default": 1},
                "row_end": {"type": "integer", "default": 50},
            },
            "required": ["masked_path"],
        },
    },
    {
        "name": "query_masked_spreadsheet",
        "description": (
            "Filter, select columns, sort, group_by and aggregate (count, count_distinct, sum, avg, min, max) "
            "a masked spreadsheet (.xlsx/.csv/.tsv). Optionally save the full result to a new masked file."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "masked_path": {"type": "string"},
                "sheet_name": {"type": "string"},
                "filters": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "column": {"type": "string"},
                            "op": {"type": "string", "enum": ["==", "!=", ">", ">=", "<", "<=", "contains", "not_contains", "in", "regex"]},
                            "value": {},
                        },
                        "required": ["column", "op", "value"],
                    },
                },
                "select_columns": {"type": "array", "items": {"type": "string"}},
                "sort_by": {"type": "string"},
                "sort_desc": {"type": "boolean", "default": False},
                "group_by": {"type": "array", "items": {"type": "string"}},
                "aggregations": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "column": {"type": "string"},
                            "func": {"type": "string", "enum": ["count", "count_distinct", "sum", "avg", "min", "max"]},
                            "alias": {"type": "string"},
                        },
                        "required": ["func"],
                    },
                },
                "limit": {"type": "integer", "default": 200},
                "offset": {"type": "integer", "default": 0},
                "save_to_masked_path": {"type": "string", "description": "Optional .pii_masked/ path to save the query result."},
                "output_sheet_name": {"type": "string", "default": "Result"},
            },
            "required": ["masked_path"],
        },
    },
    {
        "name": "join_masked_spreadsheets",
        "description": (
            "Join two masked spreadsheets (.xlsx/.csv/.tsv) on matching key columns "
            "(including #PII_NAME_*#, #PII_PHONE_*#, #PII_ID_*# token columns) and write to a masked output file."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "left_path": {"type": "string"},
                "right_path": {"type": "string"},
                "output_masked_path": {"type": "string"},
                "left_on": {"type": "string"},
                "right_on": {"type": "string"},
                "how": {"type": "string", "enum": ["inner", "left", "right", "outer"], "default": "inner"},
                "left_sheet": {"type": "string"},
                "right_sheet": {"type": "string"},
                "output_sheet_name": {"type": "string", "default": "Merged"},
            },
            "required": ["left_path", "right_path", "output_masked_path", "left_on", "right_on"],
        },
    },
    {
        "name": "create_masked_spreadsheet",
        "description": (
            "Create a clean, formatted multi-sheet .xlsx (or .csv/.tsv) inside .pii_masked/ "
            "with styled headers, auto-fitted column widths, frozen header row, and Excel formulas (=SUM(...))."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "output_masked_path": {"type": "string"},
                "sheets": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "headers": {"type": "array", "items": {"type": "string"}},
                            "rows": {"type": "array", "items": {"type": "array"}},
                        },
                        "required": ["name", "rows"],
                    },
                },
                "freeze_header": {"type": "boolean", "default": True},
            },
            "required": ["output_masked_path", "sheets"],
        },
    },
    {
        "name": "edit_masked_spreadsheet",
        "description": (
            "Update specific cells (including Excel formulas starting with '=') or append rows "
            "on an existing masked .xlsx/.csv while preserving original sheets, styles, and charts."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "masked_path": {"type": "string"},
                "output_masked_path": {"type": "string"},
                "sheet_name": {"type": "string"},
                "updates": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "cell": {"type": "string", "description": "A1-style coordinate like D2."},
                            "value": {},
                        },
                        "required": ["cell", "value"],
                    },
                },
                "append_rows": {"type": "array", "items": {"type": "array"}},
            },
            "required": ["masked_path", "output_masked_path"],
        },
    },
    {
        "name": "edit_masked_docx",
        "description": (
            "Edit a masked .docx document: replace placeholders/text across split runs, "
            "update table cells, or append paragraphs and bordered tables."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "masked_path": {"type": "string"},
                "output_masked_path": {"type": "string"},
                "replacements": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "find": {"type": "string"},
                            "replace": {"type": "string"},
                        },
                        "required": ["find", "replace"],
                    },
                },
                "table_updates": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "table_index": {"type": "integer", "default": 0},
                            "row": {"type": "integer"},
                            "col": {"type": "integer"},
                            "value": {"type": "string"},
                        },
                        "required": ["row", "col", "value"],
                    },
                },
                "append_paragraphs": {"type": "array", "items": {"type": "string"}},
                "append_table": {
                    "type": "object",
                    "properties": {
                        "headers": {"type": "array", "items": {"type": "string"}},
                        "rows": {"type": "array", "items": {"type": "array"}},
                    },
                },
            },
            "required": ["masked_path", "output_masked_path"],
        },
    },
    {
        "name": "create_masked_docx",
        "description": (
            "Create a new formatted .docx report inside .pii_masked/ from headings, paragraphs, and tables."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "output_masked_path": {"type": "string"},
                "title": {"type": "string"},
                "blocks": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "type": {"type": "string", "enum": ["heading", "paragraph", "table"]},
                            "text": {"type": "string"},
                            "level": {"type": "integer"},
                            "headers": {"type": "array", "items": {"type": "string"}},
                            "rows": {"type": "array", "items": {"type": "array"}},
                        },
                        "required": ["type"],
                    },
                },
            },
            "required": ["output_masked_path", "blocks"],
        },
    },
    {
        "name": "restore_document",
        "description": (
            "Restore all #PII_*# tokens inside a masked spreadsheet or Word document back to original PII values locally, "
            "writing the final deliverable to output_path (must be outside .pii_masked/). Never returns raw PII to context."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "masked_path": {"type": "string"},
                "output_path": {"type": "string"},
                "vault_id": {"type": "string"},
            },
            "required": ["masked_path", "output_path", "vault_id"],
        },
    },
    {
        "name": "export_redacted",
        "description": (
            "Export an irreversibly redacted copy (e.g., 张*, 138****5678, 1101**********1234) "
            "for safe external sharing, from either a masked working copy (with vault_id) or a raw source file."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "input_path": {"type": "string"},
                "output_path": {"type": "string"},
                "vault_id": {"type": "string"},
                "style": {"type": "string", "enum": ["standard", "full"], "default": "standard"},
            },
            "required": ["input_path", "output_path"],
        },
    },
    {
        "name": "match_vault_tokens",
        "description": (
            "Filter tokens inside a vault locally by safe predicates (e.g. surname prefix, phone last 4 digits, "
            "email domain, ID birth year/gender/province) and return ONLY matching #PII_*# tokens."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "vault_id": {"type": "string"},
                "category": {"type": "string", "enum": list(DEFAULT_CATEGORIES)},
                "starts_with": {"type": "string"},
                "ends_with": {"type": "string"},
                "email_domain": {"type": "string"},
                "id_gender": {"type": "string", "enum": ["男", "女"]},
                "id_province": {"type": "string"},
                "id_birth_year_min": {"type": "integer"},
                "id_birth_year_max": {"type": "integer"},
            },
            "required": ["vault_id"],
        },
    },
    {
        "name": "extract_id_demographics",
        "description": (
            "Extract strictly non-identifying demographics (province, birth_year, gender) for #PII_ID_*# tokens "
            "in a vault without exposing ID card digits or full birthdates."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "vault_id": {"type": "string"},
                "tokens": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["vault_id"],
        },
    },
    {
        "name": "audit_no_pii_leak",
        "description": (
            "Scan a file locally to confirm no unmasked PII remains. Returns only counts and cell/paragraph locations."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string"},
                "vault_id": {"type": "string"},
            },
            "required": ["file_path"],
        },
    },
]


def _call_tool(name: str, args: dict[str, Any]) -> Any:
    if name == "prepare_masked_copy":
        return prepare_masked_copy(
            source_paths=args["source_paths"],
            vault_id=args.get("vault_id"),
            output_dir=args.get("output_dir"),
            extra_name_columns=args.get("extra_name_columns", ()),
            extra_names=args.get("extra_names", ()),
            exclude_words=args.get("exclude_words", ()),
            categories=args.get("categories", DEFAULT_CATEGORIES),
        )
    if name == "inspect_masked_document":
        return inspect_masked_document(
            masked_path=args["masked_path"],
            sheet_name=args.get("sheet_name"),
            row_start=int(args.get("row_start", 1)),
            row_end=int(args.get("row_end", 50)),
        )
    if name == "query_masked_spreadsheet":
        return query_masked_spreadsheet(
            masked_path=args["masked_path"],
            sheet_name=args.get("sheet_name"),
            filters=args.get("filters"),
            select_columns=args.get("select_columns"),
            sort_by=args.get("sort_by"),
            sort_desc=bool(args.get("sort_desc", False)),
            group_by=args.get("group_by"),
            aggregations=args.get("aggregations"),
            limit=int(args.get("limit", 200)),
            offset=int(args.get("offset", 0)),
            save_to_masked_path=args.get("save_to_masked_path"),
            output_sheet_name=args.get("output_sheet_name", "Result"),
        )
    if name == "join_masked_spreadsheets":
        return join_masked_spreadsheets(
            left_path=args["left_path"],
            right_path=args["right_path"],
            output_masked_path=args["output_masked_path"],
            left_on=args["left_on"],
            right_on=args["right_on"],
            how=args.get("how", "inner"),
            left_sheet=args.get("left_sheet"),
            right_sheet=args.get("right_sheet"),
            output_sheet_name=args.get("output_sheet_name", "Merged"),
        )
    if name == "create_masked_spreadsheet":
        return create_masked_spreadsheet(
            output_masked_path=args["output_masked_path"],
            sheets=args["sheets"],
            freeze_header=bool(args.get("freeze_header", True)),
        )
    if name == "edit_masked_spreadsheet":
        return edit_masked_spreadsheet(
            masked_path=args["masked_path"],
            output_masked_path=args["output_masked_path"],
            sheet_name=args.get("sheet_name"),
            updates=args.get("updates", ()),
            append_rows=args.get("append_rows", ()),
        )
    if name == "edit_masked_docx":
        return edit_masked_docx(
            masked_path=args["masked_path"],
            output_masked_path=args["output_masked_path"],
            replacements=args.get("replacements", ()),
            table_updates=args.get("table_updates", ()),
            append_paragraphs=args.get("append_paragraphs", ()),
            append_table=args.get("append_table"),
        )
    if name == "create_masked_docx":
        return create_masked_docx(
            output_masked_path=args["output_masked_path"],
            title=args.get("title"),
            blocks=args["blocks"],
        )
    if name == "restore_document":
        return restore_document(
            masked_path=args["masked_path"],
            output_path=args["output_path"],
            vault_id=args["vault_id"],
        )
    if name == "export_redacted":
        return export_redacted(
            input_path=args["input_path"],
            output_path=args["output_path"],
            vault_id=args.get("vault_id"),
            style=args.get("style", "standard"),
        )
    if name == "match_vault_tokens":
        v = PIIVault.load(args["vault_id"])
        tokens = v.match_tokens(
            category=args.get("category"),
            starts_with=args.get("starts_with"),
            ends_with=args.get("ends_with"),
            email_domain=args.get("email_domain"),
            id_gender=args.get("id_gender"),
            id_province=args.get("id_province"),
            id_birth_year_min=args.get("id_birth_year_min"),
            id_birth_year_max=args.get("id_birth_year_max"),
        )
        return {"vault_id": v.vault_id, "matched_count": len(tokens), "tokens": tokens}
    if name == "extract_id_demographics":
        v = PIIVault.load(args["vault_id"])
        demo = v.extract_demographics(tokens=args.get("tokens"))
        return {"vault_id": v.vault_id, "count": len(demo), "demographics": demo}
    if name == "audit_no_pii_leak":
        return audit_document(args["file_path"], vault_id=args.get("vault_id"))
    raise ValueError(f"Unknown tool: {name}")


def _handle_request(req: dict[str, Any]) -> dict[str, Any] | None:
    req_id = req.get("id")
    method = req.get("method", "")
    params = req.get("params") or {}

    if method == "initialize":
        client_ver = params.get("protocolVersion", "2024-11-05")
        proto = client_ver if client_ver in SUPPORTED_PROTOCOLS else "2024-11-05"
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": proto,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "doc-pii-guard", "version": "0.1.0"},
            },
        }
    if method == "notifications/initialized" or method.startswith("notifications/"):
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        tool_name = params.get("name", "")
        tool_args = params.get("arguments") or {}
        try:
            res = _call_tool(tool_name, tool_args)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(res, ensure_ascii=False, indent=2)}],
                    "isError": False,
                },
            }
        except Exception as exc:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": f"Error in {tool_name}: {exc}"}],
                    "isError": True,
                },
            }

    if req_id is None:
        return None
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


def _write_message(resp: dict[str, Any], use_content_length: bool) -> None:
    body = json.dumps(resp, ensure_ascii=False).encode("utf-8")
    if use_content_length:
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        sys.stdout.buffer.write(header + body)
    else:
        sys.stdout.buffer.write(body + b"\n")
    sys.stdout.buffer.flush()


def main() -> None:
    buf = sys.stdin.buffer
    while True:
        line = buf.readline()
        if not line:
            break
        stripped = line.strip()
        if not stripped:
            continue
        use_cl = False
        if stripped.lower().startswith(b"content-length:"):
            use_cl = True
            length = int(stripped.split(b":", 1)[1].strip())
            while True:
                hdr_line = buf.readline()
                if not hdr_line or hdr_line in (b"\r\n", b"\n"):
                    break
            raw_body = buf.read(length)
        else:
            raw_body = stripped

        try:
            req = json.loads(raw_body.decode("utf-8"))
        except Exception as exc:
            sys.stderr.write(f"Invalid JSON-RPC input: {exc}\n")
            continue

        try:
            resp = _handle_request(req)
        except Exception:
            sys.stderr.write(traceback.format_exc())
            resp = (
                {
                    "jsonrpc": "2.0",
                    "id": req.get("id"),
                    "error": {"code": -32603, "message": "Internal server error"},
                }
                if req.get("id") is not None
                else None
            )

        if resp is not None:
            _write_message(resp, use_cl)


if __name__ == "__main__":
    main()
