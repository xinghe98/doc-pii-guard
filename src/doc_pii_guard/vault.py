"""Local PII token mapping vault and masked-file registry."""

from __future__ import annotations

import json
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any

from .pii import (
    CATEGORY_PREFIX,
    TOKEN_RE,
    parse_id_demographics,
    redact_value,
)

MASKED_DIR_NAME = ".pii_masked"


def get_data_root() -> Path:
    """Resolve persistent data directory outside any user workspace."""
    override = os.environ.get("DOC_PII_GUARD_DATA") or os.environ.get("PLUGIN_DATA")
    if override:
        return Path(override).expanduser().resolve()
    return (Path.home() / ".local" / "share" / "doc-pii-guard").resolve()


def get_vaults_dir() -> Path:
    d = get_data_root() / "vaults"
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(get_data_root(), 0o700)
        os.chmod(d, 0o700)
    except OSError:
        pass
    return d


def get_registry_path() -> Path:
    get_vaults_dir()
    return get_data_root() / "masked_registry.json"


def _write_private_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)


def load_registry() -> dict[str, Any]:
    reg_path = get_registry_path()
    if not reg_path.exists():
        return {"files": {}, "dirs": []}
    try:
        with open(reg_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {"files": {}, "dirs": []}
        data.setdefault("files", {})
        data.setdefault("dirs", [])
        return data
    except (OSError, json.JSONDecodeError):
        return {"files": {}, "dirs": []}


def register_masked_file(masked_path: Path, source_path: Path, vault_id: str) -> None:
    reg = load_registry()
    real_p = masked_path.resolve()
    m_real = str(real_p)
    m_dir = str(real_p.parent)
    try:
        st = real_p.stat()
        mtime_ns = st.st_mtime_ns
        size = st.st_size
    except OSError:
        mtime_ns = 0
        size = 0
    reg["files"][m_real] = {
        "vault_id": vault_id,
        "source_path": str(source_path.resolve()),
        "registered_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "mtime_ns": mtime_ns,
        "size": size,
    }
    if m_dir not in reg["dirs"]:
        reg["dirs"].append(m_dir)
    _write_private_json(get_registry_path(), reg)


def is_registered_and_fresh(path: Path) -> bool:
    """Return True iff `path` is explicitly registered and unmodified since registration."""
    try:
        real = path.resolve()
        st = real.stat()
    except OSError:
        return False
    reg = load_registry()
    entry = reg.get("files", {}).get(str(real))
    if not entry:
        return False
    return entry.get("mtime_ns") == st.st_mtime_ns and entry.get("size") == st.st_size


def is_registered_masked_path(path: Path) -> bool:
    """Return True iff `path` is a registered masked file or lives inside `.pii_masked/`."""
    try:
        real = path.resolve()
    except OSError:
        return False
    # Never allow paths inside the vault data root!
    data_root = get_data_root()
    if real == data_root or data_root in real.parents:
        return False
    if MASKED_DIR_NAME in real.parts:
        return True
    reg = load_registry()
    if str(real) in reg.get("files", {}):
        return True
    for d in reg.get("dirs", []):
        try:
            dp = Path(d).resolve()
            if real == dp or dp in real.parents:
                return True
        except OSError:
            continue
    return False


class PIIVault:
    """Bidirectional reversible mapping between real PII values and opaque tokens."""

    def __init__(self, vault_id: str | None = None) -> None:
        self.vault_id = vault_id or f"v_{time.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        self.created_at = time.strftime("%Y-%m-%dT%H:%M:%S")
        self.updated_at = self.created_at
        self.counters: dict[str, int] = {k: 0 for k in CATEGORY_PREFIX}
        self.forward: dict[str, dict[str, str]] = {k: {} for k in CATEGORY_PREFIX}
        self.reverse: dict[str, dict[str, str]] = {}
        self.known_names: list[str] = []
        self.files: list[dict[str, Any]] = []

    @classmethod
    def vault_path(cls, vault_id: str) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9_\-]+", vault_id):
            raise ValueError(f"Invalid vault_id: {vault_id}")
        return get_vaults_dir() / f"{vault_id}.json"

    @classmethod
    def load(cls, vault_id: str) -> "PIIVault":
        path = cls.vault_path(vault_id)
        if not path.exists():
            raise FileNotFoundError(f"Vault not found: {vault_id}")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        v = cls(vault_id=data["vault_id"])
        v.created_at = data.get("created_at", v.created_at)
        v.updated_at = data.get("updated_at", v.updated_at)
        v.counters.update(data.get("counters", {}))
        for k, mapping in data.get("forward", {}).items():
            v.forward[k] = dict(mapping)
        v.reverse = dict(data.get("reverse", {}))
        v.known_names = list(data.get("known_names", []))
        v.files = list(data.get("files", []))
        return v

    @classmethod
    def load_or_create(cls, vault_id: str | None) -> "PIIVault":
        if vault_id:
            path = cls.vault_path(vault_id)
            if path.exists():
                return cls.load(vault_id)
            return cls(vault_id=vault_id)
        return cls()

    def save(self) -> Path:
        self.updated_at = time.strftime("%Y-%m-%dT%H:%M:%S")
        payload = {
            "vault_id": self.vault_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "counters": self.counters,
            "forward": self.forward,
            "reverse": self.reverse,
            "known_names": self.known_names,
            "files": self.files,
        }
        path = self.vault_path(self.vault_id)
        _write_private_json(path, payload)
        return path

    def get_or_create_token(self, category: str, canonical: str, raw: str) -> str:
        cat = category if category in CATEGORY_PREFIX else "CUSTOM"
        cat_map = self.forward.setdefault(cat, {})
        if canonical in cat_map:
            return cat_map[canonical]
        self.counters[cat] = self.counters.get(cat, 0) + 1
        prefix = CATEGORY_PREFIX[cat]
        token = f"#PII_{prefix}_{self.counters[cat]:04d}#"
        cat_map[canonical] = token
        self.reverse[token] = {
            "category": cat,
            "canonical": canonical,
            "raw": raw,
        }
        if cat == "NAME" and raw.strip() and raw.strip() not in self.known_names:
            self.known_names.append(raw.strip())
        return token

    def record_file(self, source_path: Path, masked_path: Path, fmt: str, extra: dict[str, Any] | None = None) -> None:
        entry: dict[str, Any] = {
            "source_path": str(source_path.resolve()),
            "masked_path": str(masked_path.resolve()),
            "format": fmt,
            "processed_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        if extra:
            entry.update(extra)
        self.files = [f for f in self.files if f.get("masked_path") != entry["masked_path"]]
        self.files.append(entry)

    def restore_text(self, text: str) -> tuple[str, int, list[str]]:
        """Replace tokens in `text` with original values.

        Returns (restored_text, replaced_count, unresolved_tokens).
        """
        if not text or "#PII_" not in text:
            return text, 0, []
        replaced = 0
        unresolved: list[str] = []

        def _repl(match: re.Match[str]) -> str:
            nonlocal replaced
            tok = match.group(0)
            entry = self.reverse.get(tok)
            if entry is not None:
                replaced += 1
                return entry["raw"]
            unresolved.append(tok)
            return tok

        return TOKEN_RE.sub(_repl, text), replaced, unresolved

    def redact_text_tokens(self, text: str, style: str = "standard") -> tuple[str, int]:
        """Replace tokens in `text` with irreversible masked values (e.g. 张*)."""
        if not text or "#PII_" not in text:
            return text, 0
        replaced = 0

        def _repl(match: re.Match[str]) -> str:
            nonlocal replaced
            tok = match.group(0)
            entry = self.reverse.get(tok)
            if entry is not None:
                replaced += 1
                return redact_value(entry["category"], entry["raw"], style=style)
            return "***"

        return TOKEN_RE.sub(_repl, text), replaced

    def all_raw_values(self) -> list[tuple[str, str]]:
        """Return list of (category, raw_value) for local audit checks only."""
        out: list[tuple[str, str]] = []
        for entry in self.reverse.values():
            out.append((entry["category"], entry["raw"]))
        return out

    def match_tokens(
        self,
        *,
        category: str | None = None,
        starts_with: str | None = None,
        ends_with: str | None = None,
        email_domain: str | None = None,
        id_gender: str | None = None,
        id_province: str | None = None,
        id_birth_year_min: int | None = None,
        id_birth_year_max: int | None = None,
    ) -> list[str]:
        """Filter tokens locally without ever returning raw PII strings."""
        matched: list[str] = []
        for token, entry in self.reverse.items():
            cat = entry["category"]
            if category and cat != category:
                continue
            raw = entry["raw"]
            canon = entry["canonical"]
            if starts_with and not (raw.startswith(starts_with) or canon.startswith(starts_with)):
                continue
            if ends_with and not (raw.endswith(ends_with) or canon.endswith(ends_with)):
                continue
            if email_domain:
                if cat != "EMAIL" or "@" not in canon:
                    continue
                if canon.split("@", 1)[1].lower() != email_domain.lower().lstrip("@"):
                    continue
            if any(v is not None for v in (id_gender, id_province, id_birth_year_min, id_birth_year_max)):
                if cat != "ID_CARD":
                    continue
                demo = parse_id_demographics(canon)
                if not demo:
                    continue
                if id_gender and demo["gender"] != id_gender:
                    continue
                if id_province and id_province not in str(demo["province"]):
                    continue
                by = int(demo["birth_year"])
                if id_birth_year_min is not None and by < id_birth_year_min:
                    continue
                if id_birth_year_max is not None and by > id_birth_year_max:
                    continue
            matched.append(token)
        return matched

    def extract_demographics(self, tokens: list[str] | None = None) -> dict[str, dict[str, Any]]:
        """Return non-identifying ID demographics keyed by token."""
        target = tokens if tokens is not None else [
            t for t, e in self.reverse.items() if e["category"] == "ID_CARD"
        ]
        result: dict[str, dict[str, Any]] = {}
        for tok in target:
            entry = self.reverse.get(tok)
            if not entry or entry["category"] != "ID_CARD":
                continue
            demo = parse_id_demographics(entry["canonical"])
            if demo:
                result[tok] = demo
        return result
