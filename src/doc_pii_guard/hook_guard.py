"""Strict PreToolUse hook guarding raw spreadsheets/Word docs and PII vaults."""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
from pathlib import Path
from typing import Any

from .vault import MASKED_DIR_NAME, get_data_root, is_registered_masked_path

DOC_EXTS = {
    ".xlsx",
    ".xls",
    ".xlsm",
    ".xlsb",
    ".csv",
    ".tsv",
    ".docx",
    ".doc",
    ".odt",
    ".ods",
    ".rtf",
}

DOC_EXT_PATTERN = re.compile(
    r"([A-Za-z0-9_~./\\\-\u4e00-\u9fff*?]+\.(?:xlsx|xls|xlsm|xlsb|csv|tsv|docx|doc|odt|ods|rtf))(?![A-Za-z0-9_])",
    re.IGNORECASE,
)

SCRIPT_EXTS = {".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".ts", ".rb", ".pl"}

VAULT_MARKERS = (
    "masked_registry.json",
    "doc-pii-guard/vaults",
    ".local/share/doc-pii-guard",
    "PLUGIN_DATA",
    "DOC_PII_GUARD_DATA",
)


def _allow() -> dict[str, Any]:
    return {"decision": "allow"}


def _deny(reason: str) -> dict[str, Any]:
    return {"decision": "deny", "reason": reason}


def _resolve(path_str: str, cwd: str) -> Path:
    p = Path(path_str).expanduser()
    if not p.is_absolute():
        p = Path(cwd) / p
    return p.resolve()


def _is_under(path: Path, root: Path) -> bool:
    try:
        pr = path.resolve()
        rr = root.resolve()
        return pr == rr or rr in pr.parents
    except OSError:
        return False


def _is_vault_reference(text: str, cwd: str) -> bool:
    data_root = get_data_root()
    if str(data_root) in text:
        return True
    for marker in VAULT_MARKERS:
        if marker in text:
            return True
    # Also check token paths resolving inside data_root.
    for tok in _tokenize_cmd(text):
        cleaned = tok.strip("\"'()[]{}=,;:")
        if not cleaned:
            continue
        if "/" in cleaned or "\\" in cleaned:
            try:
                if _is_under(_resolve(cleaned, cwd), data_root):
                    return True
            except OSError:
                pass
    return False


def _tokenize_cmd(cmd: str) -> list[str]:
    try:
        return shlex.split(cmd)
    except ValueError:
        return re.findall(r"""[^\s"'`]+|"[^"]*"|'[^']*'""", cmd)


def _is_plugin_internal_path(path: Path) -> bool:
    plugin_root = os.environ.get("PLUGIN_ROOT")
    candidates = [Path(__file__).resolve().parents[2]]
    if plugin_root:
        candidates.append(Path(plugin_root).resolve())
    for root in candidates:
        for sub in ("tests", "src", "scripts"):
            if _is_under(path, root / sub):
                return True
    return False


QUOTED_DOC_PATTERN = re.compile(
    r"""["']([^"'\n\r]+\.(?:xlsx|xls|xlsm|xlsb|csv|tsv|docx|doc|odt|ods|rtf))["']""",
    re.IGNORECASE,
)


def _check_single_doc_ref(cleaned: str, cwd: str, source_desc: str) -> str | None:
    cleaned = cleaned.strip("\"'`()[]{}=,;:")
    if "=" in cleaned:
        cleaned = cleaned.split("=", 1)[-1].strip("\"'`")
    if not cleaned:
        return None
    if "*" in cleaned or "?" in cleaned:
        if MASKED_DIR_NAME not in cleaned:
            return (
                f"已拦截{source_desc}中的文档通配符「{cleaned}」，以防直接读取未脱敏的电子表格或 Word 文档。"
                "请先使用 doc-pii-guard MCP 工具 prepare_masked_copy 生成 .pii_masked/ 脱敏副本。"
            )
        return None
    cand_path = _resolve(cleaned, cwd)
    if not is_registered_masked_path(cand_path):
        return (
            f"已拦截{source_desc}直接访问未脱敏文档「{cleaned}」以防姓名、身份证号、电话等敏感信息泄漏。"
            "请先调用 doc-pii-guard MCP 工具 prepare_masked_copy 生成 .pii_masked/ 脱敏副本，再仅操作 .pii_masked/ 内的副本，"
            "完成后用 restore_document 还原输出。"
        )
    return None


def _check_doc_mentions(text: str, cwd: str, source_desc: str, *, is_shell_cmd: bool = False) -> str | None:
    """Return a denial reason if `text` references any unmasked document or doc glob."""
    # 1. For shell commands, shlex tokens preserve quoted paths containing spaces.
    covered_spans: list[tuple[int, int]] = []
    if is_shell_cmd:
        for tok in _tokenize_cmd(text):
            cleaned = tok.strip("\"'`()[]{}=,;:")
            if "=" in cleaned:
                cleaned = cleaned.split("=", 1)[-1].strip("\"'`")
            ext = Path(cleaned.rstrip("*?")).suffix.lower() if cleaned else ""
            if ext in DOC_EXTS:
                reason = _check_single_doc_ref(cleaned, cwd, source_desc)
                if reason:
                    return reason
                # If shell token was valid masked path, skip re-scanning its tail substring.
                idx = text.find(cleaned)
                if idx >= 0:
                    covered_spans.append((idx, idx + len(cleaned)))

    # 2. Scan quoted string literals (handles paths with spaces inside Python/JS scripts).
    for m in QUOTED_DOC_PATTERN.finditer(text):
        covered_spans.append((m.start(1), m.end(1)))
        reason = _check_single_doc_ref(m.group(1), cwd, source_desc)
        if reason:
            return reason

    # 3. Fallback scan for unquoted path references (ignoring already covered quoted spans).
    for m in DOC_EXT_PATTERN.finditer(text):
        s, e = m.start(1), m.end(1)
        if any(cs <= s and e <= ce for cs, ce in covered_spans):
            continue
        reason = _check_single_doc_ref(m.group(1), cwd, source_desc)
        if reason:
            return reason
    return None


def evaluate_hook(payload: dict[str, Any]) -> dict[str, Any]:
    tool_call = payload.get("toolCall") or {}
    tool_name = str(tool_call.get("name") or "").lower()
    args = tool_call.get("args") or {}
    cwd = str(payload.get("cwd") or os.getcwd())
    data_root = get_data_root()

    # 1. File read/search/write/edit tools.
    if tool_name in {"read_file", "view_file", "grep_search", "write_file", "edit_file"}:
        path_candidates: list[str] = []
        for key in ("Path", "path", "AbsolutePath", "TargetFile", "file_path", "SearchPath", "DirectoryPath"):
            val = args.get(key)
            if isinstance(val, str) and val.strip():
                path_candidates.append(val.strip())

        for p_str in path_candidates:
            if _is_vault_reference(p_str, cwd):
                return _deny("已拦截：禁止访问 doc-pii-guard 脱敏映射库与密钥目录。")
            resolved = _resolve(p_str, cwd)
            if _is_under(resolved, data_root):
                return _deny("已拦截：禁止访问 doc-pii-guard 脱敏映射库与密钥目录。")
            if resolved.suffix.lower() in DOC_EXTS:
                if not is_registered_masked_path(resolved):
                    return _deny(
                        f"已拦截直接操作原始文档「{resolved.name}」以防姓名、身份证号、电话等敏感信息泄漏。"
                        "请先调用 doc-pii-guard MCP 工具 prepare_masked_copy 生成 .pii_masked/ 脱敏工作副本，"
                        "并在脱敏副本上分析/加工，最后调用 restore_document 还原输出。"
                    )

        if tool_name == "grep_search":
            includes = args.get("Includes") or args.get("includes") or ""
            inc_str = " ".join(includes) if isinstance(includes, list) else str(includes)
            for ext in DOC_EXTS:
                if ext in inc_str.lower():
                    search_p = str(args.get("SearchPath") or args.get("Path") or "")
                    if MASKED_DIR_NAME not in search_p:
                        return _deny(
                            f"已拦截 grep_search 直接检索原始 {ext} 文档。请先调用 prepare_masked_copy 生成 .pii_masked/ 脱敏副本。"
                        )
        return _allow()

    # 2. Shell command execution.
    if tool_name == "run_command":
        cmd = str(args.get("CommandLine") or args.get("command") or "")
        if not cmd.strip():
            return _allow()
        if _is_vault_reference(cmd, cwd):
            return _deny("已拦截：禁止通过终端命令访问 doc-pii-guard 脱敏映射库。")

        doc_reason = _check_doc_mentions(cmd, cwd, "命令", is_shell_cmd=True)
        if doc_reason:
            return _deny(doc_reason)

        # Inspect any local scripts executed by the command (e.g., python3 helper.py).
        for tok in _tokenize_cmd(cmd):
            cleaned = tok.strip("\"'`()[]{}=,;:")
            if not cleaned:
                continue
            p = Path(cleaned)
            if p.suffix.lower() in SCRIPT_EXTS:
                script_path = _resolve(cleaned, cwd)
                if _is_plugin_internal_path(script_path):
                    continue
                if script_path.is_file() and script_path.stat().st_size <= 512 * 1024:
                    try:
                        body = script_path.read_text(encoding="utf-8", errors="ignore")
                    except OSError:
                        continue
                    if _is_vault_reference(body, str(script_path.parent)):
                        return _deny(f"已拦截：脚本「{script_path.name}」引用了受保护的脱敏映射库。")
                    s_reason = _check_doc_mentions(body, str(script_path.parent), f"脚本「{script_path.name}」")
                    if s_reason:
                        return _deny(s_reason)
        return _allow()

    return _allow()


def main() -> None:
    try:
        raw = sys.stdin.read()
        payload = json.loads(raw) if raw.strip() else {}
    except Exception as exc:
        sys.stdout.write(json.dumps(_deny(f"doc-pii-guard hook 输入解析失败，安全阻断: {exc}"), ensure_ascii=False))
        sys.stdout.flush()
        return

    result = evaluate_hook(payload)
    sys.stdout.write(json.dumps(result, ensure_ascii=False))
    sys.stdout.flush()


if __name__ == "__main__":
    main()
