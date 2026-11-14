"""PII detection, canonical normalization, reversible tokenization, and redaction."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence

TOKEN_RE = re.compile(r"#PII_(?:NAME|ID|PHONE|BANK|EMAIL|CUSTOM)_[0-9A-Za-z_]+#")

CATEGORY_PREFIX = {
    "NAME": "NAME",
    "ID_CARD": "ID",
    "PHONE": "PHONE",
    "BANK_CARD": "BANK",
    "EMAIL": "EMAIL",
    "CUSTOM": "CUSTOM",
}

DEFAULT_CATEGORIES = ("NAME", "ID_CARD", "PHONE", "BANK_CARD", "EMAIL")

# Common placeholders that should never be treated as real PII values.
SKIP_VALUES = {
    "",
    "-",
    "--",
    "---",
    "/",
    "\\",
    "无",
    "暂无",
    "空",
    "未知",
    "不详",
    "待定",
    "待填",
    "待补充",
    "n/a",
    "na",
    "none",
    "null",
    "nil",
    "合计",
    "总计",
    "小计",
    "汇总",
    "平均",
    "平均值",
    "备注",
    "序号",
    "编号",
}

# Column / field header keywords -> PII category.
HEADER_POSITIVE: dict[str, tuple[str, ...]] = {
    "NAME": (
        "姓名",
        "名字",
        "人员姓名",
        "员工姓名",
        "客户姓名",
        "患者姓名",
        "联系人",
        "紧急联系人",
        "负责人",
        "经办人",
        "办理人",
        "审批人",
        "申请人",
        "申报人",
        "法人",
        "法定代表人",
        "法人代表",
        "收件人",
        "寄件人",
        "收款人",
        "付款人",
        "户名",
        "开户人",
        "开户名",
        "持卡人",
        "制表人",
        "审核人",
        "复核人",
        "填表人",
        "签署人",
        "签字人",
        "当事人",
        "被保险人",
        "投保人",
        "受益人",
        "借款人",
        "担保人",
        "真实姓名",
        "会员姓名",
        "学生姓名",
        "家长姓名",
        "full name",
        "contact name",
        "employee name",
        "customer name",
        "recipient",
        "cardholder",
    ),
    "ID_CARD": (
        "身份证",
        "身份证号",
        "身份证号码",
        "居民身份证",
        "证件号",
        "证件号码",
        "id card",
        "id_card",
        "id number",
        "identity",
        "national id",
    ),
    "PHONE": (
        "电话",
        "手机",
        "手机号",
        "手机号码",
        "联系电话",
        "移动电话",
        "联系方式",
        "固定电话",
        "座机",
        "住宅电话",
        "办公电话",
        "phone",
        "mobile",
        "tel",
        "telephone",
        "cell",
    ),
    "BANK_CARD": (
        "银行卡",
        "银行卡号",
        "卡号",
        "银行账号",
        "银行账户",
        "收款账号",
        "付款账号",
        "工资卡",
        "工资卡号",
        "储蓄卡",
        "信用卡",
        "bank card",
        "bank account",
        "card number",
        "account number",
    ),
    "EMAIL": (
        "邮箱",
        "电子邮箱",
        "邮件",
        "电子邮件",
        "email",
        "e-mail",
        "mail",
    ),
}

# Exclusions to prevent matching non-personal entity names like "公司名称".
NAME_HEADER_EXCLUSIONS = (
    "公司名称",
    "企业名称",
    "单位名称",
    "机构名称",
    "组织名称",
    "部门名称",
    "项目名称",
    "产品名称",
    "商品名称",
    "文件名称",
    "文件名",
    "表格名称",
    "表名",
    "岗位名称",
    "职位名称",
    "课程名称",
    "活动名称",
    "银行名称",
    "开户行名称",
    "开户银行",
    "城市名称",
    "地区名称",
    "地址名称",
    "账号名称",
    "费用名称",
    "科目名称",
    "渠道名称",
    "品牌名称",
    "学校名称",
    "医院名称",
    "company name",
    "department name",
    "product name",
    "project name",
    "file name",
    "bank name",
    "sheet name",
    "course name",
)

# Valid Chinese province prefixes (GB/T 2260).
VALID_PROVINCE_CODES = {
    "11", "12", "13", "14", "15",
    "21", "22", "23",
    "31", "32", "33", "34", "35", "36", "37",
    "41", "42", "43", "44", "45", "46",
    "50", "51", "52", "53", "54",
    "61", "62", "63", "64", "65",
    "71", "81", "82",
}

PROVINCE_NAMES = {
    "11": "北京市", "12": "天津市", "13": "河北省", "14": "山西省", "15": "内蒙古自治区",
    "21": "辽宁省", "22": "吉林省", "23": "黑龙江省",
    "31": "上海市", "32": "江苏省", "33": "浙江省", "34": "安徽省", "35": "福建省",
    "36": "江西省", "37": "山东省",
    "41": "河南省", "42": "湖北省", "43": "湖南省", "44": "广东省", "45": "广西壮族自治区",
    "46": "海南省",
    "50": "重庆市", "51": "四川省", "52": "贵州省", "53": "云南省", "54": "西藏自治区",
    "61": "陕西省", "62": "甘肃省", "63": "青海省", "64": "宁夏回族自治区", "65": "新疆维吾尔自治区",
    "71": "台湾省", "81": "香港特别行政区", "82": "澳门特别行政区",
}

COMMON_SURNAMES = set(
    "赵钱孙李周吴郑王冯陈褚卫蒋沈韩杨朱秦尤许何吕施张孔曹严华金魏陶姜"
    "戚谢邹喻柏水窦章云苏潘葛奚范彭郎鲁韦昌马苗凤花方俞任袁柳酆鲍史唐"
    "费廉岑薛雷贺倪汤滕殷罗毕郝邬安常乐于时傅皮卞齐康伍余元卜顾孟平黄"
    "和穆萧尹姚邵湛汪祁毛禹狄米贝明臧计伏成戴谈宋茅庞熊纪舒屈项祝董梁"
    "杜阮蓝闵席季麻强贾路娄危江童颜郭梅盛林刁钟徐邱骆高夏蔡田樊胡凌霍"
    "虞万支柯昝管卢莫经房裘缪干解应宗丁宣贲邓郁单杭洪包诸左石崔吉钮龚"
    "程嵇邢滑裴陆荣翁荀羊於惠甄曲家封芮羿储靳汲邴糜松井段富巫乌焦巴弓"
    "牧隗山谷车侯宓蓬全郗班仰秋仲伊宫宁仇栾暴甘钭厉戎祖武符刘景詹束龙"
    "叶幸司韶郜黎蓟薄印宿白怀蒲邰从鄂索咸籍赖卓蔺屠蒙池乔阴郁胥能苍双"
    "闻莘党翟谭贡劳逄姬申扶堵冉宰郦雍却璩桑桂濮牛寿通边扈燕冀郏浦尚农"
    "温别庄晏柴瞿阎充慕连茹习宦艾鱼容向古易慎戈廖庾终暨居衡步都耿满弘"
    "匡国文寇广禄阙东欧殳沃利蔚越夔隆师巩厍聂晁勾敖融冷訾辛阚那简饶空"
    "曾毋沙乜养鞠须丰巢关蒯相查后荆红游竺权逯盖益桓公"
)

COMPOUND_SURNAMES = (
    "欧阳", "太史", "端木", "上官", "司马", "东方", "独孤", "南宫", "万俟",
    "闻人", "夏侯", "诸葛", "尉迟", "公羊", "赫连", "澹台", "皇甫", "宗政",
    "濮阳", "公冶", "太叔", "申屠", "公孙", "慕容", "仲孙", "钟离", "长孙",
    "宇文", "司徒", "鲜于", "司空", "闾丘", "子车", "亓官", "司寇", "巫马",
    "公西", "颛孙", "壤驷", "公良", "漆雕", "乐正", "宰父", "谷梁", "拓跋",
    "夹谷", "轩辕", "令狐", "段干", "百里", "呼延", "东郭", "南门", "羊舌",
    "微生", "公户", "公玉", "公仪", "梁丘", "公仲", "公上", "公门", "公山",
    "公坚", "左丘", "公伯", "西门", "公祖", "第五", "公乘", "贯丘", "公皙",
    "南荣", "东里", "东宫", "仲长", "子书", "子桑", "即墨", "达奚", "褚师",
)

# Common non-name words that happen to start with a Chinese surname.
NON_NAME_STOPWORDS = {
    "人员", "人工", "人力", "人民", "人民币", "张贴", "张望", "张数", "张开",
    "王牌", "王朝", "王子", "李子", "赵州", "周报", "周一", "周二", "周三",
    "周四", "周五", "周六", "周日", "周末", "周期", "周边", "周围", "周年",
    "陈列", "陈述", "陈旧", "杨树", "林木", "林场", "森林", "高峰", "高级",
    "高原", "高额", "高低", "高度", "高速", "高校", "高管", "黄昏", "黄金",
    "白银", "白色", "白天", "刘海", "马路", "马上", "马达", "牛排", "牛肉",
    "羊绒", "羊毛", "金矿", "金额", "金融", "金钱", "金属", "金牌", "银牌",
    "银行", "钱款", "钱包", "孙子", "胡同", "朱红", "蓝天", "蓝色", "蓝图",
    "绿茶", "绿色", "江河", "江南", "江苏", "江西", "浙江", "河南", "河北",
    "湖南", "湖北", "山东", "山西", "广东", "广西", "云南", "贵州", "四川",
    "陕西", "甘肃", "青海", "新疆", "西藏", "宁夏", "海南", "北京", "上海",
    "天津", "重庆", "深圳", "广州", "杭州", "南京", "成都", "武汉", "西安",
    "苏州", "公司", "公安", "公告", "公共", "公开", "公平", "公正", "公斤",
    "公里", "方面", "方向", "方案", "方式", "方法", "方便", "万一", "万元",
    "万分", "千万", "百万", "亿万", "今天", "今日", "今年", "今早", "今晚",
    "明天", "明日", "明年", "明显", "明确", "明细", "说明", "证明", "姓名",
    "名字", "名称", "名单", "文件", "文档", "文化", "文明", "文本", "文字",
    "合同", "合作", "合计", "合格", "合适", "合理", "常驻", "常见", "常用",
    "经常", "正常", "异常", "平常", "史料", "历史", "史诗", "古今", "古代",
    "古典", "全新", "全部", "全额", "全面", "安全", "平安", "安排", "安装",
    "安慰", "安保", "安定", "平摊", "平均", "平台", "平时", "平板", "平衡",
    "联系", "联合", "联网", "联系电话", "联系地址", "手机号", "身份证",
    "银行卡", "电子邮箱", "负责人", "经办人", "联系人", "申请人", "收件人",
    "寄件人", "法定代表人", "性别", "年龄", "出生", "部门", "职务", "地址",
    "邮箱", "电话", "手机", "卡号", "账号", "账户", "工资", "薪资", "奖金",
    "备注", "序号", "编号", "日期", "时间", "状态", "类型", "备注信息",
}

# Regex definitions
EMAIL_RE = re.compile(r"(?<![A-Za-z0-9._%+\-])([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})(?![A-Za-z0-9._%+\-])")

# 18-digit and 15-digit Chinese resident ID card regexes.
ID18_RE = re.compile(
    r"(?<![0-9A-Za-z])([1-8]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx])(?![0-9A-Za-z])"
)
ID15_RE = re.compile(
    r"(?<![0-9A-Za-z])([1-8]\d{5}\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3})(?![0-9A-Za-z])"
)

# Phone numbers: mainland mobile (+86 optional, separators optional) & Chinese landline.
MOBILE_RE = re.compile(
    r"(?<!\d)((?:\+?86[\s\-]?)?1[3-9]\d(?:[\s\-]?\d{4}){2})(?!\d)"
)
LANDLINE_RE = re.compile(
    r"(?<!\d)(0\d{2,3}[\-\s]\d{7,8})(?!\d)"
)

# Bank cards: 16 to 19 digits, optionally grouped by spaces/hyphens in 4s or similar.
BANK_CARD_RE = re.compile(
    r"(?<!\d)(\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}(?:[\s\-]?\d{1,3})?)(?!\d)"
)

# Context-labeled Chinese/English personal name patterns.
NAME_LABEL_PREFIX = (
    r"(?:姓\s*名|员工姓名|客户姓名|患者姓名|会员姓名|真实姓名|联系人|紧急联系人|"
    r"负责人|经办人|办理人|审批人|申请人|法定代表人|法人代表|委托代理人|"
    r"收件人|寄件人|收款人|付款人|户\s*名|开户人|持卡人|制表人|审核人|"
    r"签署人|签\s*字|签\s*名|当事人|借款人|担保人|员工|客户)"
)
NAME_STOP_SUFFIX_LOOKAHEAD = (
    r"(?=$|[\s，,。；;、|/（）\(\)\[\]：:\d]|先生|女士|同志|老师|"
    r"电话|手机|身份证|证件|银行卡|卡号|邮箱|地址|部门|职务|性别|男|女|出生|年龄)"
)
LABELED_ZH_NAME_RE = re.compile(
    rf"({NAME_LABEL_PREFIX}\s*[：:]\s*)([\u4e00-\u9fff]{{2,5}}(?:[·•][\u4e00-\u9fff]{{2,10}})?)"
    rf"{NAME_STOP_SUFFIX_LOOKAHEAD}"
)
LABELED_EN_NAME_RE = re.compile(
    r"((?:Full\s+Name|Contact\s+Name|Employee\s+Name|Name)\s*[：:]\s*)"
    r"([A-Za-z][A-Za-z.\-']{1,20}(?:\s+[A-Za-z][A-Za-z.\-']{1,20}){0,2})"
    r"(?=$|[\s,;|\)\]\r\n])",
    re.IGNORECASE,
)

# Unlabeled Chinese name right before an honorific or parenthesized phone/ID.
HONORIFIC_NAME_RE = re.compile(
    r"(?<![\u4e00-\u9fff])([\u4e00-\u9fff]{2,3})(?=(?:先生|女士|同志))"
)
PAREN_CONTACT_NAME_RE = re.compile(
    r"(?<![\u4e00-\u9fff])([\u4e00-\u9fff]{2,4})(?=\s*[（\(]\s*(?:1[3-9]\d|\+?86|0\d{2,3}[\-\s]|[1-8]\d{5}(?:19|20)))"
)


@dataclass(frozen=True)
class PIISpan:
    start: int
    end: int
    category: str
    raw_value: str
    canonical_value: str


ORG_SUFFIX_RE = re.compile(
    r"(?:有限公司|有限责任公司|股份有限公司|集团有限公司|公司|集团|工厂|工作室|事务所|"
    r"研究院|研究所|设计院|学院|大学|医院|卫生院|诊所|银行|支行|分行|营业部|"
    r"政府|财政局|税务局|公安局|法院|检察院|委员会|协会|商会|基金会|合作社|中心|"
    r"Co\.,?\s*Ltd\.?|Inc\.?|LLC|Corp\.?|Ltd\.?|GmbH)$",
    re.IGNORECASE,
)


def is_organization_name(text: str) -> bool:
    """Return True if `text` looks like a company/institution rather than a person."""
    s = text.strip()
    if len(s) < 4:
        return False
    return bool(ORG_SUFFIX_RE.search(s))


def is_skip_value(text: str) -> bool:
    s = text.strip()
    if not s:
        return True
    if TOKEN_RE.fullmatch(s):
        return True
    return s.lower() in SKIP_VALUES


def classify_header(header_text: str) -> str | None:
    """Classify a column or form key header into a PII category, or None."""
    if not header_text:
        return None
    raw = re.sub(r"\s+", " ", header_text.strip())
    # Real column/form headers are concise labels, never prose sentences, emails, or long numbers.
    if not raw or len(raw) > 24 or re.search(r"[，。！？；@]|#PII_|\d{4,}", raw):
        return None
    low = raw.lower()
    # Exact/substring exclusions first for NAME-like non-personal entity headers.
    is_non_personal_name = any(excl in low for excl in NAME_HEADER_EXCLUSIONS)

    # Check specific non-name categories before generic NAME ("Name" appears in "Bank Name" etc.).
    for cat in ("ID_CARD", "BANK_CARD", "PHONE", "EMAIL"):
        for kw in HEADER_POSITIVE[cat]:
            if kw in low:
                return cat

    if not is_non_personal_name:
        for kw in HEADER_POSITIVE["NAME"]:
            if kw in low:
                return "NAME"
        # Single-word exact "name" header.
        if low in {"name", "姓名", "名字"}:
            return "NAME"
    return None


def validate_id18_checksum(id_str: str) -> bool:
    if len(id_str) != 18:
        return False
    weights = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
    check_map = "10X98765432"
    try:
        total = sum(int(id_str[i]) * weights[i] for i in range(17))
    except ValueError:
        return False
    return check_map[total % 11] == id_str[17].upper()


def is_plausible_id_card(id_str: str, strict_context: bool = False) -> bool:
    s = id_str.strip().upper()
    if len(s) == 18:
        if s[:2] not in VALID_PROVINCE_CODES:
            return False
        if strict_context:
            return validate_id18_checksum(s)
        # Valid province + plausible birth date (1900-2029) suffices unless strictly required.
        year = int(s[6:10])
        return 1900 <= year <= 2029
    if len(s) == 15:
        return s[:2] in VALID_PROVINCE_CODES
    return False


def luhn_check(digits: str) -> bool:
    if not digits.isdigit():
        return False
    total = 0
    reverse = digits[::-1]
    for idx, ch in enumerate(reverse):
        n = int(ch)
        if idx % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def is_plausible_bank_card(raw: str, context_text: str = "", start: int = 0) -> bool:
    digits = re.sub(r"[\s\-]", "", raw)
    if not (16 <= len(digits) <= 19) or not digits.isdigit():
        return False
    # Exclude if it matches an 18-digit ID card structure.
    if len(digits) == 18 and is_plausible_id_card(digits):
        return False
    # Check surrounding context window for explicit bank/card keywords.
    window = context_text[max(0, start - 20) : min(len(context_text), start + len(raw) + 12)]
    has_kw = bool(re.search(r"银行|卡号|银行卡|储蓄卡|信用卡|账号|账户|card|bank|acct", window, re.I))
    if has_kw:
        return True
    # Without keyword context, require standard BIN prefix + valid Luhn checksum.
    if digits[0] in {"3", "4", "5", "6", "9"} and luhn_check(digits):
        return True
    return False


def is_plausible_zh_name(candidate: str, allow_any_zh: bool = False) -> bool:
    s = re.sub(r"\s+", "", candidate.strip())
    if not s or is_skip_value(s):
        return False
    if s in NON_NAME_STOPWORDS:
        return False
    if TOKEN_RE.search(s):
        return False
    if allow_any_zh:
        return 2 <= len(s) <= 20
    # Strict check for free-text surname heuristics.
    if "·" in s or "•" in s:
        return bool(re.fullmatch(r"[\u4e00-\u9fff]{2,5}[·•][\u4e00-\u9fff]{2,10}", s))
    if not re.fullmatch(r"[\u4e00-\u9fff]{2,4}", s):
        return False
    if len(s) >= 3 and s[:2] in COMPOUND_SURNAMES:
        return True
    return s[0] in COMMON_SURNAMES and len(s) in (2, 3)


def canonicalize_value(category: str, raw_value: str) -> str:
    s = raw_value.strip()
    if category == "ID_CARD":
        return re.sub(r"\s+", "", s).upper()
    if category == "PHONE":
        digits = re.sub(r"[\s\-]", "", s)
        if digits.startswith("+86"):
            digits = digits[3:]
        elif digits.startswith("86") and len(digits) == 13 and digits[2] == "1":
            digits = digits[2:]
        return digits
    if category == "BANK_CARD":
        return re.sub(r"[\s\-]", "", s)
    if category == "EMAIL":
        return s.lower()
    if category == "NAME":
        if re.search(r"[\u4e00-\u9fff]", s):
            return re.sub(r"\s+", "", s)
        return re.sub(r"\s+", " ", s)
    return s


def redact_value(category: str, raw_value: str, style: str = "standard") -> str:
    """Produce an irreversible masked display form (for external sharing)."""
    if style == "full":
        return "***"
    s = raw_value.strip()
    if category == "NAME":
        if re.search(r"[\u4e00-\u9fff]", s):
            clean = re.sub(r"\s+", "", s)
            if len(clean) <= 1:
                return "*"
            if len(clean) == 2:
                return clean[0] + "*"
            return clean[0] + "*" * (len(clean) - 2) + clean[-1]
        parts = s.split()
        if len(parts) >= 2:
            return parts[0] + " " + " ".join(p[0] + "*" * max(1, len(p) - 1) for p in parts[1:])
        return s[0] + "*" * max(2, len(s) - 1)
    if category == "ID_CARD":
        c = canonicalize_value("ID_CARD", s)
        if len(c) >= 10:
            return c[:4] + "*" * (len(c) - 8) + c[-4:]
        return "*" * len(c)
    if category == "PHONE":
        c = canonicalize_value("PHONE", s)
        if len(c) == 11 and c.startswith("1"):
            return c[:3] + "****" + c[-4:]
        if len(c) >= 7:
            return c[:3] + "*" * (len(c) - 6) + c[-3:]
        return "*" * len(c)
    if category == "BANK_CARD":
        c = canonicalize_value("BANK_CARD", s)
        if len(c) >= 10:
            return c[:4] + "*" * (len(c) - 8) + c[-4:]
        return "*" * len(c)
    if category == "EMAIL":
        if "@" in s:
            local, domain = s.split("@", 1)
            prefix = local[:1] if local else "*"
            return f"{prefix}***@{domain}"
        return "***"
    return "***"


def parse_id_demographics(id_str: str) -> dict[str, object] | None:
    """Extract strictly non-identifying demographics from an 18/15-digit Chinese ID."""
    c = canonicalize_value("ID_CARD", id_str)
    if len(c) == 18 and c[:17].isdigit():
        prov = PROVINCE_NAMES.get(c[:2], "未知")
        birth_year = int(c[6:10])
        gender = "男" if int(c[16]) % 2 == 1 else "女"
        return {
            "province": prov,
            "birth_year": birth_year,
            "gender": gender,
        }
    if len(c) == 15 and c.isdigit():
        prov = PROVINCE_NAMES.get(c[:2], "未知")
        birth_year = 1900 + int(c[6:8])
        gender = "男" if int(c[14]) % 2 == 1 else "女"
        return {
            "province": prov,
            "birth_year": birth_year,
            "gender": gender,
        }
    return None


def _overlaps(span_start: int, span_end: int, occupied: list[tuple[int, int]]) -> bool:
    for s, e in occupied:
        if span_start < e and span_end > s:
            return True
    return False


def find_pii_spans(
    text: str,
    *,
    column_category: str | None = None,
    known_names: Iterable[str] = (),
    extra_names: Iterable[str] = (),
    exclude_words: Iterable[str] = (),
    categories: Sequence[str] = DEFAULT_CATEGORIES,
) -> list[PIISpan]:
    """Detect non-overlapping PII spans in `text`."""
    if not text or not text.strip():
        return []
    # Never alter an already-tokenized value cleanly; detect unmasked segments around tokens.
    cat_set = set(categories)
    excl_set = {w.strip() for w in exclude_words if w and w.strip()} | NON_NAME_STOPWORDS
    occupied: list[tuple[int, int]] = [(m.start(), m.end()) for m in TOKEN_RE.finditer(text)]
    spans: list[PIISpan] = []

    def add_span(s: int, e: int, cat: str, raw: str) -> None:
        if cat not in cat_set:
            return
        if s >= e or _overlaps(s, e, occupied):
            return
        if raw.strip() in excl_set or is_skip_value(raw):
            return
        occupied.append((s, e))
        spans.append(
            PIISpan(
                start=s,
                end=e,
                category=cat,
                raw_value=raw,
                canonical_value=canonicalize_value(cat, raw),
            )
        )

    # 0. Column-level whole-cell classification when column header directly indicates PII.
    stripped = text.strip()
    lead = len(text) - len(text.lstrip())
    tail = lead + len(stripped)
    if column_category and column_category in cat_set and not is_skip_value(stripped):
        if not TOKEN_RE.fullmatch(stripped) and stripped not in excl_set:
            if column_category == "NAME":
                # Avoid masking pure numbers, organization names (in mixed B2B/B2C payee columns), or long clauses.
                if (
                    not re.fullmatch(r"[\d.\-+%]+", stripped)
                    and len(stripped) <= 30
                    and not is_organization_name(stripped)
                ):
                    # Handle multiple names separated by 、 / , ; in a single cell?
                    if re.search(r"[、,，;；/]", stripped):
                        for m in re.finditer(r"[^、,，;；/\s]+", text):
                            part = m.group(0)
                            if not is_skip_value(part) and part not in excl_set and not re.fullmatch(r"[\d.\-+%]+", part):
                                add_span(m.start(), m.end(), "NAME", part)
                    else:
                        add_span(lead, tail, "NAME", stripped)
            elif column_category == "ID_CARD":
                if re.fullmatch(r"[A-Za-z0-9\-\s]{6,22}", stripped) and re.search(r"\d{5,}", stripped):
                    add_span(lead, tail, "ID_CARD", stripped)
            elif column_category == "PHONE":
                if re.fullmatch(r"[\+\d\-\s\(\)]{7,20}", stripped) and len(re.sub(r"\D", "", stripped)) >= 7:
                    add_span(lead, tail, "PHONE", stripped)
            elif column_category == "BANK_CARD":
                digits = re.sub(r"[\s\-]", "", stripped)
                if digits.isdigit() and 12 <= len(digits) <= 22:
                    add_span(lead, tail, "BANK_CARD", stripped)
            elif column_category == "EMAIL":
                if "@" in stripped and EMAIL_RE.search(stripped):
                    add_span(lead, tail, "EMAIL", stripped)

    # 1. Emails (unambiguous).
    if "EMAIL" in cat_set:
        for m in EMAIL_RE.finditer(text):
            add_span(m.start(1), m.end(1), "EMAIL", m.group(1))

    # 2. ID Cards (18-digit then 15-digit).
    if "ID_CARD" in cat_set:
        for m in ID18_RE.finditer(text):
            val = m.group(1)
            if is_plausible_id_card(val):
                add_span(m.start(1), m.end(1), "ID_CARD", val)
        for m in ID15_RE.finditer(text):
            val = m.group(1)
            # 15-digit IDs only outside numeric tables unless context or column indicates ID.
            window = text[max(0, m.start(1) - 12) : m.start(1)]
            if column_category == "ID_CARD" or re.search(r"身份证|证件|ID", window, re.I):
                if is_plausible_id_card(val):
                    add_span(m.start(1), m.end(1), "ID_CARD", val)

    # 3. Phones (mobile + landline).
    if "PHONE" in cat_set:
        for m in MOBILE_RE.finditer(text):
            add_span(m.start(1), m.end(1), "PHONE", m.group(1))
        for m in LANDLINE_RE.finditer(text):
            add_span(m.start(1), m.end(1), "PHONE", m.group(1))

    # 4. Bank Cards (after ID_CARD so 18-digit IDs are already claimed).
    if "BANK_CARD" in cat_set:
        for m in BANK_CARD_RE.finditer(text):
            val = m.group(1)
            if is_plausible_bank_card(val, text, m.start(1)):
                add_span(m.start(1), m.end(1), "BANK_CARD", val)

    # 5. Names in free text / labeled fields / known-names propagation.
    if "NAME" in cat_set:
        for m in LABELED_ZH_NAME_RE.finditer(text):
            cand = m.group(2)
            if is_plausible_zh_name(cand, allow_any_zh=True) and cand not in excl_set:
                add_span(m.start(2), m.end(2), "NAME", cand)

        for m in LABELED_EN_NAME_RE.finditer(text):
            cand = m.group(2).strip()
            if cand and cand not in excl_set and not is_skip_value(cand):
                add_span(m.start(2), m.end(2), "NAME", cand)

        for m in PAREN_CONTACT_NAME_RE.finditer(text):
            cand = m.group(1)
            if is_plausible_zh_name(cand, allow_any_zh=False) and cand not in excl_set:
                add_span(m.start(1), m.end(1), "NAME", cand)

        for m in HONORIFIC_NAME_RE.finditer(text):
            cand = m.group(1)
            if is_plausible_zh_name(cand, allow_any_zh=False) and cand not in excl_set:
                add_span(m.start(1), m.end(1), "NAME", cand)

        # Known names (from columns, labeled fields, or extra_names), longest first.
        all_known = sorted(
            {
                n.strip()
                for n in (*known_names, *extra_names)
                if n and len(n.strip()) >= 2 and n.strip() not in excl_set
            },
            key=len,
            reverse=True,
        )
        for name in all_known:
            if re.search(r"[\u4e00-\u9fff]", name):
                pattern = re.compile(re.escape(name))
            else:
                pattern = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])")
            for m in pattern.finditer(text):
                # Guard short 2-char Chinese known names from matching inside obvious non-person compounds.
                if len(name) == 2 and m.end() < len(text) and text[m.end()] in "期值率度量区":
                    continue
                add_span(m.start(), m.end(), "NAME", m.group(0))

    spans.sort(key=lambda sp: sp.start)
    return spans


def apply_replacements(
    text: str,
    spans: Sequence[PIISpan],
    token_allocator: Callable[[str, str, str], str],
) -> tuple[str, list[tuple[int, int, str]]]:
    """Replace `spans` in `text` using `token_allocator(category, canonical, raw)`.

    Returns (masked_text, list_of_(start, end, replacement_token)).
    """
    if not spans:
        return text, []
    pieces: list[str] = []
    replacements: list[tuple[int, int, str]] = []
    cursor = 0
    for sp in spans:
        pieces.append(text[cursor : sp.start])
        token = token_allocator(sp.category, sp.canonical_value, sp.raw_value)
        pieces.append(token)
        replacements.append((sp.start, sp.end, token))
        cursor = sp.end
    pieces.append(text[cursor:])
    return "".join(pieces), replacements
