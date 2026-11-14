# Doc PII Guard

一个面向 Antigravity (`agy`) 的本地隐私脱敏插件：在处理电子表格（`.xlsx` / `.xlsm` / `.xls` / `.csv` / `.tsv`）和 Word 文档（`.docx` / `.doc`）时，自动将**姓名、身份证号码、电话号码、银行卡号、电子邮箱**在本地脱敏为可逆一致假名令牌（如 `#PII_NAME_0001#`、`#PII_ID_0001#`、`#PII_PHONE_0001#`），在严防敏感信息进入大模型上下文的同时，保持完整的表格分析、跨表合并、公式编辑、报表生成与本地自动还原能力。

## 核心特性

- **可逆假名脱敏 + 本地自动还原**：同一人物、身份证号、手机号在同批次多张表和 Word 文档中映射为同一个令牌，Agent 可正常完成统计、去重、分组汇总、`join` 合并、写 Excel 公式和生成 Word 报告，最终通过 `restore_document` 在本地无缝还原为真实信息交付。
- **双模式导出**：除默认“可逆脱敏 + 本地还原”外，也支持 `export_redacted` 导出不可逆打码版（如 `张*`、`138****5678`、`1101**********1234`）用于对外安全分享。
- **严格 `PreToolUse` Hook 防泄漏拦截**：自动阻止 `read_file`、`view_file`、`grep_search`、`write_file`、`edit_file` 与 `run_command`（含所执行 `.py`/`.sh`/`.js` 脚本内容检查）直接访问原始未脱敏文档或脱敏映射库（Vault），强制通过 `.pii_masked/` 脱敏副本与 MCP 工具作业。
- **无损 OOXML 与零第三方依赖**：纯 Python 标准库直接解析和修改 `.xlsx`（保留公式、样式、图表、批注）与 `.docx`（支持跨 `<w:r><w:t>` 拆分运行段还原、表格列头识别、横向键值表单、页眉页脚与文本框），无需安装额外 Python 依赖包。
- **隐私安全条件查询**：支持 `match_vault_tokens`（按姓氏前缀、手机尾号、邮箱域名、出生年份/性别/省份筛选并返回令牌）与 `extract_id_demographics`（仅提取省份、出生年、性别，不暴露完整证件号与出生月日）。

## 插件结构

```text
doc-pii-guard/
├── plugin.json                 # 插件清单
├── mcp_config.json             # MCP Stdio 服务配置
├── hooks.json                  # PreToolUse 严格拦截配置
├── rules/AGENTS.md             # 常驻脱敏作业规则
├── skills/doc-pii-guard/       # 脱敏与表格/Word 作业指南
├── scripts/                    # MCP 与 Hook 启动脚本
├── assets/logo.svg             # 插件图标
├── src/doc_pii_guard/          # 核心脱敏引擎、MCP Server、Hook 守卫
└── tests/                      # 单元测试与端到端测试
```

## 安装与验证

```bash
agy plugin validate /Users/xinghe/.gemini/antigravity/scratch/doc-pii-guard --strict
agy plugin install /Users/xinghe/.gemini/antigravity/scratch/doc-pii-guard
```
