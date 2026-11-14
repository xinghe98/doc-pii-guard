---
name: doc-pii-guard
description: >-
  Reversible PII desensitization workflow for spreadsheets (.xlsx, .xlsm, .xls, .csv, .tsv)
  and Word documents (.docx, .doc). Use whenever inspecting, summarizing, filtering,
  joining, editing, or generating spreadsheets or Word documents containing names,
  ID card numbers, phone numbers, bank cards, or emails.
---

# Doc PII Guard Workflow

This workflow keeps all raw PII strictly local while allowing full spreadsheet analysis, joins, formulas, formatting, and Word report generation.

## Standard Workflow

1. **Create a Masked Working Copy (`prepare_masked_copy`)**
   - Pass all related files together in `source_paths` (or supply an existing `vault_id`) so the same person, ID card, phone number, bank card, or email receives the exact same token (`#PII_NAME_0001#`, `#PII_ID_0001#`, `#PII_PHONE_0001#`, `#PII_BANK_0001#`, `#PII_EMAIL_0001#`) across every sheet and document.
   - If the spreadsheet uses an unusual personal name column header, pass `extra_name_columns`.
   - Record the returned `vault_id` and `.pii_masked/` file paths.

2. **Work Freely on `.pii_masked/` Copies**
   - **Inspect structure & data**: `inspect_masked_document` (supports sheet selection and row pagination).
   - **Filter, sort, group & aggregate**: `query_masked_spreadsheet` (supports `==`, `!=`, `>`, `>=`, `<`, `<=`, `contains`, `in`, `regex`, `group_by`, `count`/`count_distinct`/`sum`/`avg`/`min`/`max`, and `save_to_masked_path`).
   - **Cross-table joins**: `join_masked_spreadsheets` (`inner`, `left`, `right`, `outer`) on token columns (`姓名`, `身份证号`, `手机号`) or normal keys.
   - **Create or update spreadsheets**: `create_masked_spreadsheet` (supports multi-sheet workbooks, styled headers, auto-widths, freeze panes, and `=SUM(...)` Excel formulas) or `edit_masked_spreadsheet` (preserves original workbook styles, charts, and formulas).
   - **Work on Word documents**: `edit_masked_docx` (find/replace placeholders across split runs, update table cells, append paragraphs/tables) or `create_masked_docx`.
   - **Custom Python scripts**: Allowed via `run_command` as long as scripts only read/write paths inside `.pii_masked/`.

3. **Privacy-Safe Criteria Queries (Optional)**
   - **Filter by surname / phone tail / email domain / ID demographics**: call `match_vault_tokens` to get matching `#PII_*#` tokens without seeing raw PII.
   - **Age / gender / province statistics from ID cards**: call `extract_id_demographics` to obtain `{province, birth_year, gender}` per `#PII_ID_*#` token.

4. **Deliver Final Result (`restore_document` or `export_redacted`)**
   - When the user needs the finished spreadsheet or Word report with real values intact, call `restore_document(masked_path, output_path, vault_id)` targeting a path outside `.pii_masked/`.
   - When the user wants an anonymized copy for external sharing (e.g., `张*`, `138****5678`, `1101**********1234`), call `export_redacted`.
   - Call `audit_no_pii_leak` on masked intermediates or redacted exports whenever verification is needed.
