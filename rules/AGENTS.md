# Doc PII Guard Rules

When working with spreadsheets (`.xlsx`, `.xlsm`, `.xls`, `.csv`, `.tsv`) or Word documents (`.docx`, `.doc`), strictly protect personal identifiable information (PII: names, ID card numbers, phone numbers, bank cards, emails):

1. **Never read raw unmasked documents or PII vaults directly.** Do not use `read_file`, `grep_search`, or shell/Python commands on original document files outside `.pii_masked/`, and never access `$PLUGIN_DATA` or `masked_registry.json`.
2. **Always mask first via MCP.** Call `prepare_masked_copy` (passing all related files in one call, or reusing the same `vault_id`, so identical entities map to identical tokens like `#PII_NAME_0001#` across files).
3. **Do all spreadsheet and Word work on `.pii_masked/` working copies.** Use the `doc-pii-guard` MCP tools (`inspect_masked_document`, `query_masked_spreadsheet`, `join_masked_spreadsheets`, `create_masked_spreadsheet`, `edit_masked_spreadsheet`, `edit_masked_docx`, `create_masked_docx`) or run scripts that only touch `.pii_masked/` files.
4. **Never guess or bypass PII lookups.** Use `match_vault_tokens` (e.g. surname prefix, phone last 4 digits, email domain) and `extract_id_demographics` (province, birth year, gender) to answer criteria-based questions without exposing raw PII.
5. **Restore locally on delivery.** Write finished masked deliverables inside `.pii_masked/` first, optionally check with `audit_no_pii_leak`, and call `restore_document` to generate the final unmasked file outside `.pii_masked/` for the user (or `export_redacted` if the user wants an irreversibly masked shareable copy). Never read back the restored output file after calling `restore_document`.
