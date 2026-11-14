"""Comprehensive unit and end-to-end tests for doc-pii-guard."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from doc_pii_guard.docx_proc import create_docx_file, inspect_docx  # noqa: E402
from doc_pii_guard.engine import (  # noqa: E402
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
from doc_pii_guard.hook_guard import evaluate_hook  # noqa: E402
from doc_pii_guard.pii import (  # noqa: E402
    classify_header,
    find_pii_spans,
    parse_id_demographics,
    redact_value,
    validate_id18_checksum,
)
from doc_pii_guard.vault import PIIVault  # noqa: E402
from doc_pii_guard.xlsx_proc import create_xlsx_file, inspect_xlsx  # noqa: E402


def _make_split_run_docx(path: Path) -> None:
    """Create a .docx with split <w:t> runs, vertical + KV tables, and header."""
    path.parent.mkdir(parents=True, exist_ok=True)
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        '<Override PartName="/word/header1.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/>'
        '</Types>'
    )
    root_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="word/document.xml"/>'
        '</Relationships>'
    )
    doc_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/header" '
        'Target="header1.xml"/>'
        '</Relationships>'
    )
    header1 = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:p><w:r><w:t>内部档案 - 联系人：张三 13812345678</w:t></w:r></w:p>'
        '</w:hdr>'
    )
    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<w:body>'
        # Split phone across 3 runs & split ID across 2 runs
        '<w:p>'
        '<w:r><w:t>经核实，张三的手机为</w:t></w:r>'
        '<w:r><w:t>138</w:t></w:r>'
        '<w:r><w:t>1234</w:t></w:r>'
        '<w:r><w:t>5678</w:t></w:r>'
        '<w:r><w:t>，身份证号为</w:t></w:r>'
        '<w:r><w:t>110101</w:t></w:r>'
        '<w:r><w:t>199001011234</w:t></w:r>'
        '<w:r><w:t>，邮箱 zhangsan@example.com。</w:t></w:r>'
        '</w:p>'
        # Unlabeled prose referencing someone discovered in another file
        '<w:p><w:r><w:t>另请王五先生及今天人员共同审阅，避开用电高峰期。主责人：{{LEAD_TOKEN}}</w:t></w:r></w:p>'
        # Horizontal KV table
        '<w:tbl>'
        '<w:tr>'
        '<w:tc><w:p><w:r><w:t>姓名</w:t></w:r></w:p></w:tc>'
        '<w:tc><w:p><w:r><w:t>李四</w:t></w:r></w:p></w:tc>'
        '<w:tc><w:p><w:r><w:t>联系电话</w:t></w:r></w:p></w:tc>'
        '<w:tc><w:p><w:r><w:t>010-88886666</w:t></w:r></w:p></w:tc>'
        '</w:tr>'
        '</w:tbl>'
        # Vertical table
        '<w:tbl>'
        '<w:tr>'
        '<w:tc><w:p><w:r><w:t>部门名称</w:t></w:r></w:p></w:tc>'
        '<w:tc><w:p><w:r><w:t>姓名</w:t></w:r></w:p></w:tc>'
        '<w:tc><w:p><w:r><w:t>银行卡号</w:t></w:r></w:p></w:tc>'
        '</w:tr>'
        '<w:tr>'
        '<w:tc><w:p><w:r><w:t>研发部</w:t></w:r></w:p></w:tc>'
        '<w:tc><w:p><w:r><w:t>欧阳娜</w:t></w:r></w:p></w:tc>'
        '<w:tc><w:p><w:r><w:t>6222020200001234567</w:t></w:r></w:p></w:tc>'
        '</w:tr>'
        '</w:tbl>'
        '<w:sectPr><w:headerReference w:type="default" r:id="rId1"/></w:sectPr>'
        '</w:body>'
        '</w:document>'
    )
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types.encode("utf-8"))
        zf.writestr("_rels/.rels", root_rels.encode("utf-8"))
        zf.writestr("word/_rels/document.xml.rels", doc_rels.encode("utf-8"))
        zf.writestr("word/header1.xml", header1.encode("utf-8"))
        zf.writestr("word/document.xml", document.encode("utf-8"))


def _make_numeric_phone_xlsx(path: Path) -> None:
    """Create an .xlsx containing title banner row, numeric phone cell, and SUM formula."""
    create_xlsx_file(
        path,
        [
            {
                "name": "员工薪资",
                "headers": ["员工信息汇总表", "", "", "", "", "", ""],
                "rows": [
                    ["序号", "部门名称", "姓名", "身份证号", "手机号", "邮箱", "奖金"],
                    [1, "研发部", "张三", "110101199001011234", 13812345678, "zhangsan@example.com", 5000],
                    [2, "财务部", "李四", "31010119880512234X", "139-0013-9000", "lisi@example.com", 6200],
                    [3, "研发部", "王五", "440101199508203456", "+86 13711112222", "wangwu@example.com", 4800],
                    ["合计", "", "", "", "", "", "=SUM(G3:G5)"],
                ],
            },
            {
                "name": "备注信息",
                "headers": ["记录编号", "说明"],
                "rows": [
                    ["N1", "请张三确认银行卡 6222020200001234567 已绑定"],
                ],
            },
        ],
    )


class TestDocPIIGuard(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="test_pii_guard_")
        self.tmp_path = Path(self._tmp.name)
        self.data_dir = self.tmp_path / "vault_data"
        self._old_env = os.environ.get("DOC_PII_GUARD_DATA")
        os.environ["DOC_PII_GUARD_DATA"] = str(self.data_dir)

    def tearDown(self) -> None:
        if self._old_env is None:
            os.environ.pop("DOC_PII_GUARD_DATA", None)
        else:
            os.environ["DOC_PII_GUARD_DATA"] = self._old_env
        self._tmp.cleanup()

    def test_pii_detection_and_redaction(self) -> None:
        self.assertEqual(classify_header("员工姓名"), "NAME")
        self.assertIsNone(classify_header("部门名称"))
        self.assertIsNone(classify_header("公司名称"))
        self.assertEqual(classify_header("银行卡号"), "BANK_CARD")
        self.assertEqual(classify_header("身份证号码"), "ID_CARD")
        self.assertEqual(classify_header("联系电话"), "PHONE")
        self.assertEqual(classify_header("Email"), "EMAIL")

        self.assertTrue(validate_id18_checksum("11010519491231002X"))
        self.assertFalse(validate_id18_checksum("110105194912310021"))

        demo = parse_id_demographics("110101199001011234")
        self.assertEqual(demo, {"province": "北京市", "birth_year": 1990, "gender": "男"})

        spans = find_pii_spans(
            "联系人：张三，手机+86 138-1234-5678，身份证110101199001011234，银行卡6222020200001234567，邮箱zs@corp.cn，今天天气不错",
        )
        cats = [s.category for s in spans]
        self.assertEqual(cats, ["NAME", "PHONE", "ID_CARD", "BANK_CARD", "EMAIL"])
        self.assertNotIn("今天", [s.raw_value for s in spans])

        self.assertEqual(redact_value("NAME", "张三"), "张*")
        self.assertEqual(redact_value("NAME", "欧阳娜"), "欧*娜")
        self.assertEqual(redact_value("PHONE", "13812345678"), "138****5678")
        self.assertEqual(redact_value("ID_CARD", "110101199001011234"), "1101**********1234")

    def test_csv_gbk_mask_query_and_restore(self) -> None:
        csv_path = self.tmp_path / "staff.csv"
        rows = [
            ["序号", "部门名称", "姓名", "身份证号", "手机号", "工资"],
            ["1", "技术部", "张三", "110101199001011234", "13812345678", "15000"],
            ["2", "技术部", "李四", "31010119880512234X", "13900139000", "18000"],
            ["3", "市场部", "张三", "110101199001011234", "138-1234-5678", "12000"],
        ]
        csv_text = "\n".join(",".join(r) for r in rows)
        csv_path.write_bytes(csv_text.encode("gb18030"))

        res = prepare_masked_copy(str(csv_path))
        vault_id = res["vault_id"]
        masked_csv = Path(res["files"][0]["masked_path"])
        self.assertTrue(masked_csv.exists())
        self.assertIn(".pii_masked", masked_csv.parts)

        # Verify masked file contains ZERO raw PII.
        audit = audit_document(str(masked_csv), vault_id=vault_id)
        self.assertTrue(audit["clean"], audit)

        # Verify consistency: row 1 and row 3 ("张三", "13812345678" vs "138-1234-5678") got identical tokens!
        inspected = inspect_masked_document(str(masked_csv))
        self.assertEqual(inspected["rows"][1][2], inspected["rows"][3][2])
        self.assertEqual(inspected["rows"][1][4], inspected["rows"][3][4])
        self.assertEqual(inspected["rows"][1][1], "技术部")  # Non-PII department preserved!

        # Group by 部门名称 and sum 工资 on masked CSV.
        agg_out = masked_csv.parent / "dept_summary.masked.xlsx"
        qres = query_masked_spreadsheet(
            str(masked_csv),
            group_by=["部门名称"],
            aggregations=[
                {"column": "姓名", "func": "count_distinct", "alias": "人数"},
                {"column": "工资", "func": "sum", "alias": "总工资"},
            ],
            sort_by="总工资",
            sort_desc=True,
            save_to_masked_path=str(agg_out),
        )
        self.assertEqual(qres["rows"], [["技术部", "2", "33000"], ["市场部", "1", "12000"]])
        self.assertTrue(agg_out.exists())

        # Restore masked CSV back to real PII outside .pii_masked/.
        restored_csv = self.tmp_path / "staff_restored.csv"
        rinfo = restore_document(str(masked_csv), str(restored_csv), vault_id)
        self.assertGreaterEqual(rinfo["restored_count"], 9)
        self.assertEqual(rinfo["unresolved_tokens"], [])
        restored_text = restored_csv.read_text(encoding="utf-8-sig")
        self.assertIn("张三", restored_text)
        self.assertIn("110101199001011234", restored_text)
        self.assertNotIn("#PII_", restored_text)

    def test_xlsx_mask_join_edit_create_and_restore(self) -> None:
        staff_xlsx = self.tmp_path / "staff.xlsx"
        bonus_xlsx = self.tmp_path / "bonus.xlsx"
        _make_numeric_phone_xlsx(staff_xlsx)
        create_xlsx_file(
            bonus_xlsx,
            [
                {
                    "name": "绩效",
                    "headers": ["姓名", "绩效等级", "补贴"],
                    "rows": [
                        ["张三", "A", 1200],
                        ["王五", "B", 800],
                    ],
                }
            ],
        )

        prep = prepare_masked_copy([str(staff_xlsx), str(bonus_xlsx)])
        vault_id = prep["vault_id"]
        masked_staff = Path(prep["files"][0]["masked_path"])
        masked_bonus = Path(prep["files"][1]["masked_path"])

        self.assertTrue(audit_document(str(masked_staff), vault_id=vault_id)["clean"])
        self.assertTrue(audit_document(str(masked_bonus), vault_id=vault_id)["clean"])

        # Inspect sheet 1 & sheet 2.
        s1 = inspect_masked_document(str(masked_staff), sheet_name="员工薪资")
        s2 = inspect_masked_document(str(masked_staff), sheet_name="备注信息")
        self.assertEqual(s1["header_row"], 2)
        zs_token = s1["rows"][2][2]  # Row 3 (index 2), Col 3 (姓名)
        self.assertTrue(zs_token.startswith("#PII_NAME_"))
        self.assertIn(zs_token, s2["rows"][1][1])  # Cross-sheet name consistency!

        # Join masked staff & masked bonus on 姓名.
        joined_masked = masked_staff.parent / "joined.masked.xlsx"
        jres = join_masked_spreadsheets(
            str(masked_staff),
            str(masked_bonus),
            str(joined_masked),
            left_on="姓名",
            right_on="姓名",
            how="inner",
        )
        self.assertEqual(jres["total_rows"], 2)

        # Edit existing masked workbook (out-of-order cell update + append row) and verify formulas survive.
        edited_masked = masked_staff.parent / "staff_edited.masked.xlsx"
        edit_masked_spreadsheet(
            str(masked_staff),
            str(edited_masked),
            sheet_name="员工薪资",
            updates=[{"cell": "G3", "value": 5500}],
            append_rows=[[4, "市场部", zs_token, "", "", "", 1000]],
        )

        # Create a brand-new formatted masked report with SUM formula.
        report_masked = masked_staff.parent / "report.masked.xlsx"
        create_masked_spreadsheet(
            str(report_masked),
            sheets=[
                {
                    "name": "汇总",
                    "headers": ["姓名", "奖金", "补贴", "合计"],
                    "rows": [
                        [zs_token, 5000, 1200, "=B2+C2"],
                    ],
                }
            ],
        )

        # Refuse restoring inside .pii_masked/!
        with self.assertRaises(ValueError):
            restore_document(str(joined_masked), str(masked_staff.parent / "evil.xlsx"), vault_id)

        # Restore joined & report deliverables outside .pii_masked/.
        final_joined = self.tmp_path / "final_joined.xlsx"
        final_report = self.tmp_path / "final_report.xlsx"
        r1 = restore_document(str(joined_masked), str(final_joined), vault_id)
        r2 = restore_document(str(report_masked), str(final_report), vault_id)
        self.assertEqual(r1["unresolved_tokens"], [])
        self.assertEqual(r2["unresolved_tokens"], [])

        insp_final_joined = inspect_xlsx(final_joined)
        names_restored = {r[2] for r in insp_final_joined["rows"][1:]}
        self.assertEqual(names_restored, {"张三", "王五"})
        phones_restored = {r[4] for r in insp_final_joined["rows"][1:]}
        self.assertIn("13812345678", phones_restored)

        # Verify formula preserved inside final_report.xlsx XML.
        with zipfile.ZipFile(final_report, "r") as zf:
            sheet_xml = zf.read("xl/worksheets/sheet1.xml").decode("utf-8")
            self.assertIn("<f>B2+C2</f>", sheet_xml)

        # Irreversible redaction export from raw file.
        redacted_xlsx = self.tmp_path / "shared_redacted.xlsx"
        export_redacted(str(staff_xlsx), str(redacted_xlsx), style="standard")
        self.assertTrue(audit_document(str(redacted_xlsx))["clean"])
        redacted_view = inspect_xlsx(redacted_xlsx)
        self.assertEqual(redacted_view["rows"][2][2], "张*")
        self.assertEqual(redacted_view["rows"][2][4], "138****5678")

    def test_docx_split_runs_and_cross_file_batch_mask_edit_restore(self) -> None:
        docx_path = self.tmp_path / "contract.docx"
        xlsx_path = self.tmp_path / "roster.xlsx"
        _make_split_run_docx(docx_path)
        _make_numeric_phone_xlsx(xlsx_path)

        # Batch mask Word doc + Excel roster together (Word first to test 2nd-pass propagation!).
        prep = prepare_masked_copy([str(docx_path), str(xlsx_path)])
        vault_id = prep["vault_id"]
        masked_docx = Path(prep["files"][0]["masked_path"])

        self.assertTrue(audit_document(str(masked_docx), vault_id=vault_id)["clean"])

        doc_view = inspect_docx(masked_docx)
        p0 = doc_view["paragraphs"][0]["text"]
        p1 = doc_view["paragraphs"][1]["text"]
        self.assertNotIn("张三", p0)
        self.assertNotIn("13812345678", p0)
        self.assertNotIn("110101199001011234", p0)
        self.assertNotIn("zhangsan@example.com", p0)
        # Cross-file learned name "王五" must be masked, while "今天" and "高峰期" remain untouched!
        self.assertNotIn("王五", p1)
        self.assertIn("今天人员", p1)
        self.assertIn("高峰期", p1)
        # Header masked!
        self.assertNotIn("张三", "\n".join(doc_view["headers_footers"].get("header1", [])))
        self.assertNotIn("13812345678", "\n".join(doc_view["headers_footers"].get("header1", [])))
        # Tables masked while 部门名称 preserved!
        self.assertEqual(doc_view["tables"][1][1][0], "研发部")
        self.assertTrue(doc_view["tables"][1][1][1].startswith("#PII_NAME_"))
        self.assertTrue(doc_view["tables"][1][1][2].startswith("#PII_BANK_"))

        # Edit masked docx placeholder and append summary table.
        vault = PIIVault.load(vault_id)
        zs_tokens = vault.match_tokens(category="NAME", starts_with="张")
        self.assertEqual(len(zs_tokens), 1)
        edited_docx = masked_docx.parent / "contract_edited.masked.docx"
        edit_masked_docx(
            str(masked_docx),
            str(edited_docx),
            replacements=[{"find": "{{LEAD_TOKEN}}", "replace": zs_tokens[0]}],
            append_paragraphs=["审批结束。"],
            append_table={"headers": ["姓名", "状态"], "rows": [[zs_tokens[0], "已通过"]]},
        )

        # Restore final Word document.
        final_docx = self.tmp_path / "contract_final.docx"
        rinfo = restore_document(str(edited_docx), str(final_docx), vault_id)
        self.assertEqual(rinfo["unresolved_tokens"], [])
        final_view = inspect_docx(final_docx)
        self.assertIn("张三", final_view["paragraphs"][0]["text"])
        self.assertIn("13812345678", final_view["paragraphs"][0]["text"])
        self.assertIn("110101199001011234", final_view["paragraphs"][0]["text"])
        self.assertIn("主责人：张三", final_view["paragraphs"][1]["text"])
        self.assertEqual(final_view["tables"][2][1], ["张三", "已通过"])

        # Also test create_masked_docx -> restore_document.
        new_masked_docx = masked_docx.parent / "summary.masked.docx"
        create_masked_docx(
            str(new_masked_docx),
            title="月度总结",
            blocks=[
                {"type": "paragraph", "text": f"本月优秀员工：{zs_tokens[0]}"},
                {"type": "table", "headers": ["姓名", "备注"], "rows": [[zs_tokens[0], "优秀"]]},
            ],
        )
        new_final_docx = self.tmp_path / "summary_final.docx"
        restore_document(str(new_masked_docx), str(new_final_docx), vault_id)
        self.assertIn("本月优秀员工：张三", inspect_docx(new_final_docx)["paragraphs"][1]["text"])

    def test_vault_safe_queries_never_leak_pii(self) -> None:
        staff_xlsx = self.tmp_path / "staff.xlsx"
        _make_numeric_phone_xlsx(staff_xlsx)
        prep = prepare_masked_copy(str(staff_xlsx))
        vault = PIIVault.load(prep["vault_id"])

        # Filter by surname "张", phone last 4 "2222", birth year <= 1989.
        zhang_toks = vault.match_tokens(category="NAME", starts_with="张")
        tail_toks = vault.match_tokens(category="PHONE", ends_with="2222")
        older_id_toks = vault.match_tokens(category="ID_CARD", id_birth_year_max=1989)
        self.assertEqual(len(zhang_toks), 1)
        self.assertEqual(len(tail_toks), 1)
        self.assertEqual(len(older_id_toks), 1)

        demo = vault.extract_demographics()
        for tok, info in demo.items():
            self.assertTrue(tok.startswith("#PII_ID_"))
            self.assertEqual(set(info.keys()), {"province", "birth_year", "gender"})

    def test_mcp_server_stdio_e2e(self) -> None:
        staff_xlsx = self.tmp_path / "staff.xlsx"
        _make_numeric_phone_xlsx(staff_xlsx)

        env = os.environ.copy()
        env["PLUGIN_ROOT"] = str(ROOT)
        env["DOC_PII_GUARD_DATA"] = str(self.data_dir)

        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "prepare_masked_copy", "arguments": {"source_paths": str(staff_xlsx)}},
            },
        ]
        stdin_payload = "\n".join(json.dumps(r) for r in requests) + "\n"
        proc = subprocess.run(
            [str(ROOT / "scripts" / "run_mcp.sh")],
            input=stdin_payload,
            capture_output=True,
            text=True,
            env=env,
            timeout=15,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = [json.loads(line) for line in proc.stdout.strip().splitlines() if line.strip()]
        self.assertEqual(len(lines), 3)  # notification produces no reply
        self.assertEqual(lines[0]["result"]["serverInfo"]["name"], "doc-pii-guard")
        tool_names = {t["name"] for t in lines[1]["result"]["tools"]}
        self.assertIn("prepare_masked_copy", tool_names)
        self.assertIn("restore_document", tool_names)
        prep_text = lines[2]["result"]["content"][0]["text"]
        self.assertFalse(lines[2]["result"]["isError"])
        # Ensure ZERO raw PII appears in MCP server response!
        for raw_pii in ("张三", "李四", "王五", "13812345678", "110101199001011234", "zhangsan@example.com"):
            self.assertNotIn(raw_pii, prep_text)

    def test_pre_tool_use_hook_strict_guard(self) -> None:
        staff_xlsx = self.tmp_path / "staff.xlsx"
        _make_numeric_phone_xlsx(staff_xlsx)
        prep = prepare_masked_copy(str(staff_xlsx))
        masked_xlsx = Path(prep["files"][0]["masked_path"])
        masked_with_spaces = masked_xlsx.parent / "员工 工资 副本.masked.xlsx"
        masked_with_spaces.write_bytes(masked_xlsx.read_bytes())

        cwd = str(self.tmp_path)

        # 1. Block direct read_file / view_file / grep_search on raw spreadsheet/Word/vault.
        for tname in ("read_file", "view_file", "grep_search", "edit_file"):
            res = evaluate_hook({"toolCall": {"name": tname, "args": {"Path": str(staff_xlsx)}}, "cwd": cwd})
            self.assertEqual(res["decision"], "deny", (tname, res))

        res_vault = evaluate_hook(
            {"toolCall": {"name": "read_file", "args": {"Path": str(self.data_dir / "masked_registry.json")}}, "cwd": cwd}
        )
        self.assertEqual(res_vault["decision"], "deny")

        # 2. Allow reading masked file (including path with spaces inside .pii_masked/).
        res_ok1 = evaluate_hook({"toolCall": {"name": "read_file", "args": {"Path": str(masked_xlsx)}}, "cwd": cwd})
        self.assertEqual(res_ok1["decision"], "allow")
        res_ok2 = evaluate_hook({"toolCall": {"name": "read_file", "args": {"Path": str(masked_with_spaces)}}, "cwd": cwd})
        self.assertEqual(res_ok2["decision"], "allow")

        # 3. Block shell commands referencing raw files, globs, smuggling, or vault.
        for bad_cmd in (
            f"cat {staff_xlsx}",
            f"cp {staff_xlsx} {masked_xlsx.parent}/smuggled.xlsx",
            "head -n 20 *.csv",
            f"cat {self.data_dir}/vaults/{prep['vault_id']}.json",
        ):
            r = evaluate_hook({"toolCall": {"name": "run_command", "args": {"CommandLine": bad_cmd}}, "cwd": cwd})
            self.assertEqual(r["decision"], "deny", bad_cmd)

        # 4. Block executing a Python script that reads raw unmasked document.
        bad_script = self.tmp_path / "sneaky.py"
        bad_script.write_text('import zipfile\nz = zipfile.ZipFile("staff.xlsx")\n', encoding="utf-8")
        r_bad_script = evaluate_hook(
            {"toolCall": {"name": "run_command", "args": {"CommandLine": f"python3 {bad_script}"}}, "cwd": cwd}
        )
        self.assertEqual(r_bad_script["decision"], "deny")

        # 5. Allow executing a Python script that ONLY accesses .pii_masked/ files (even with spaces!).
        good_script = self.tmp_path / "safe_process.py"
        good_script.write_text(
            f'p = "{masked_with_spaces}"\nprint(len(p))\n',
            encoding="utf-8",
        )
        r_good_script = evaluate_hook(
            {"toolCall": {"name": "run_command", "args": {"CommandLine": f"python3 {good_script}"}}, "cwd": cwd}
        )
        self.assertEqual(r_good_script["decision"], "allow", r_good_script)

        # 6. Allow normal shell command & normal code file read.
        self.assertEqual(
            evaluate_hook({"toolCall": {"name": "run_command", "args": {"CommandLine": "git status"}}, "cwd": cwd})["decision"],
            "allow",
        )
        self.assertEqual(
            evaluate_hook({"toolCall": {"name": "read_file", "args": {"Path": str(good_script)}}, "cwd": cwd})["decision"],
            "allow",
        )

        # 7. Subprocess smoke test on scripts/pre_tool_guard.sh directly.
        env = os.environ.copy()
        env["PLUGIN_ROOT"] = str(ROOT)
        env["DOC_PII_GUARD_DATA"] = str(self.data_dir)
        hook_proc = subprocess.run(
            [str(ROOT / "scripts" / "pre_tool_guard.sh")],
            input=json.dumps({"toolCall": {"name": "read_file", "args": {"Path": str(staff_xlsx)}}, "cwd": cwd}),
            capture_output=True,
            text=True,
            env=env,
            timeout=10,
        )
        self.assertEqual(hook_proc.returncode, 0, hook_proc.stderr)
        hook_out = json.loads(hook_proc.stdout)
        self.assertEqual(hook_out["decision"], "deny")

    def test_legacy_doc_via_textutil_if_available(self) -> None:
        import shutil

        textutil = shutil.which("textutil")
        if not textutil:
            self.skipTest("textutil not available on non-macOS")
        txt_src = self.tmp_path / "memo.txt"
        doc_src = self.tmp_path / "memo.doc"
        txt_src.write_text("姓名：张三\n电话：13812345678\n身份证：110101199001011234\n", encoding="utf-8")
        conv = subprocess.run([textutil, "-convert", "doc", "-output", str(doc_src), str(txt_src)], capture_output=True)
        if conv.returncode != 0 or not doc_src.exists():
            self.skipTest("textutil could not create .doc fixture")
        prep = prepare_masked_copy(str(doc_src))
        masked_docx = Path(prep["files"][0]["masked_path"])
        self.assertEqual(masked_docx.suffix, ".docx")
        self.assertTrue(audit_document(str(masked_docx), vault_id=prep["vault_id"])["clean"])
        final_docx = self.tmp_path / "memo_restored.docx"
        restore_document(str(masked_docx), str(final_docx), prep["vault_id"])
        text_out = "\n".join(p["text"] for p in inspect_docx(final_docx)["paragraphs"])
        self.assertIn("张三", text_out)
        self.assertIn("13812345678", text_out)
        self.assertIn("110101199001011234", text_out)


if __name__ == "__main__":
    unittest.main()
