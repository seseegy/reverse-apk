"""Parser AndroidManifest.xml hasil apktool -> ringkasan JSON untuk tab Manifest (FR-3.1 bagian dasar).

Masukannya TIDAK TEPERCAYA (berasal dari APK). Pertahanan: batas ukuran, tolak DOCTYPE/ENTITY
(XXE & billion-laughs), batas jumlah elemen/entri, dan semua teks dipotong. Tampilan di web
selalu meng-escape; parser ini hanya menghasilkan data.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
MAX_XML_BYTES = 8 * 1024 * 1024
MAX_ELEMENTS = 200_000
MAX_COMPONENTS = 3000
MAX_FILTERS = 20
MAX_FILTER_ITEMS = 25
MAX_TEXT = 300

COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")

_P = "android.permission."
# Izin runtime "berbahaya" menurut dokumentasi Android.
DANGEROUS_PERMISSIONS = frozenset(_P + p for p in (
    "READ_CALENDAR WRITE_CALENDAR CAMERA READ_CONTACTS WRITE_CONTACTS GET_ACCOUNTS "
    "ACCESS_FINE_LOCATION ACCESS_COARSE_LOCATION ACCESS_BACKGROUND_LOCATION RECORD_AUDIO "
    "READ_PHONE_STATE READ_PHONE_NUMBERS CALL_PHONE ANSWER_PHONE_CALLS READ_CALL_LOG WRITE_CALL_LOG "
    "ADD_VOICEMAIL USE_SIP PROCESS_OUTGOING_CALLS BODY_SENSORS BODY_SENSORS_BACKGROUND "
    "ACTIVITY_RECOGNITION SEND_SMS RECEIVE_SMS READ_SMS RECEIVE_WAP_PUSH RECEIVE_MMS "
    "READ_EXTERNAL_STORAGE WRITE_EXTERNAL_STORAGE ACCESS_MEDIA_LOCATION READ_MEDIA_IMAGES "
    "READ_MEDIA_VIDEO READ_MEDIA_AUDIO READ_MEDIA_VISUAL_USER_SELECTED POST_NOTIFICATIONS "
    "NEARBY_WIFI_DEVICES BLUETOOTH_CONNECT BLUETOOTH_SCAN BLUETOOTH_ADVERTISE UWB_RANGING"
).split())
# Izin khusus/sensitif yang tidak lewat dialog runtime biasa.
SPECIAL_PERMISSIONS = frozenset(_P + p for p in (
    "SYSTEM_ALERT_WINDOW REQUEST_INSTALL_PACKAGES MANAGE_EXTERNAL_STORAGE BIND_ACCESSIBILITY_SERVICE "
    "BIND_DEVICE_ADMIN WRITE_SETTINGS PACKAGE_USAGE_STATS QUERY_ALL_PACKAGES READ_LOGS "
    "INSTALL_PACKAGES DELETE_PACKAGES BIND_NOTIFICATION_LISTENER_SERVICE SCHEDULE_EXACT_ALARM "
    "USE_EXACT_ALARM FOREGROUND_SERVICE_CAMERA FOREGROUND_SERVICE_MICROPHONE"
).split())


class ManifestError(Exception):
    pass


def _clip(value: Any, limit: int = MAX_TEXT) -> str | None:
    if value is None:
        return None
    return str(value).replace("\x00", "")[:limit]


def _bool(value: str | None) -> bool | None:
    if value is None:
        return None
    v = value.strip().lower()
    if v in {"true", "-1", "0xffffffff", "1"}:
        return True
    if v in {"false", "0", "0x0"}:
        return False
    return None  # referensi (@bool/...) yang tidak bisa diputuskan secara statis


def _read_xml(path: Path) -> ET.Element:
    try:
        size = path.stat().st_size
        if size > MAX_XML_BYTES:
            raise ManifestError(f"{path.name} terlalu besar ({size} byte)")
        data = path.read_bytes()
    except OSError as exc:
        raise ManifestError(f"{path.name} tidak bisa dibaca: {type(exc).__name__}") from exc
    if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        raise ManifestError(f"{path.name} berisi DOCTYPE/ENTITY; ditolak demi keamanan")
    try:
        return ET.fromstring(data)
    except ET.ParseError as exc:
        raise ManifestError(f"{path.name} bukan XML valid: {exc}") from exc


def _attr(el: ET.Element, name: str) -> str | None:
    return el.get(ANDROID_NS + name)


def _qualify(name: str | None, package: str | None) -> str | None:
    if not name:
        return None
    name = name.strip()
    if name.startswith("."):
        return _clip((package or "") + name)
    if "." not in name and package:
        return _clip(f"{package}.{name}")
    return _clip(name)


def _read_apktool_yml(path: Path | None) -> dict[str, str]:
    """Ambil beberapa kunci dari apktool.yml tanpa dependensi YAML (format datar yang sederhana)."""
    out: dict[str, str] = {}
    if path is None:
        return out
    try:
        if path.stat().st_size > 1024 * 1024:
            return out
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    wanted = {"minSdkVersion", "targetSdkVersion", "maxSdkVersion", "versionCode", "versionName"}
    for line in text.splitlines():
        m = re.match(r"^\s{1,4}([A-Za-z]+):\s*(.*?)\s*$", line)
        if m and m.group(1) in wanted:
            out[m.group(1)] = m.group(2).strip("'\"")
    return out


def _resolve_label(raw: str | None, res_dir: Path | None) -> str | None:
    """Selesaikan @string/nama lewat res/values/strings.xml. Gagal -> None (bukan error)."""
    if not raw:
        return None
    if not raw.startswith("@string/"):
        return _clip(raw, 120) if not raw.startswith("@") else None
    if res_dir is None:
        return None
    key = raw.split("/", 1)[1]
    try:
        root = _read_xml(res_dir / "values" / "strings.xml")
    except ManifestError:
        return None
    for el in root.iter("string"):
        if el.get("name") == key:
            text = "".join(el.itertext()).strip()
            return _clip(text, 120) or None
    return None


def _intent_filters(comp: ET.Element) -> list[dict[str, list[str]]]:
    filters = []
    for f in comp.findall("intent-filter")[:MAX_FILTERS]:
        actions = [_clip(_attr(a, "name"), 200) or "" for a in f.findall("action")][:MAX_FILTER_ITEMS]
        cats = [_clip(_attr(c, "name"), 200) or "" for c in f.findall("category")][:MAX_FILTER_ITEMS]
        data = []
        for d in f.findall("data")[:MAX_FILTER_ITEMS]:
            parts = []
            scheme, host = _attr(d, "scheme"), _attr(d, "host")
            if scheme or host:
                parts.append(f"{scheme or '*'}://{host or '*'}")
            for key in ("path", "pathPrefix", "pathPattern", "mimeType", "port"):
                v = _attr(d, key)
                if v:
                    parts.append(f"{key}={v}")
            if parts:
                data.append(_clip(" ".join(parts), 200) or "")
        filters.append({"actions": actions, "categories": cats, "data": data})
    return filters


def _component(tag: str, comp: ET.Element, package: str | None, target_sdk: int | None) -> dict[str, Any]:
    explicit = _bool(_attr(comp, "exported"))
    filters = _intent_filters(comp)
    has_filter = bool(comp.findall("intent-filter"))
    if explicit is not None:
        exported, source = explicit, "explicit"
    elif tag == "provider":
        # Sebelum API 17 provider default-nya exported; setelahnya tidak.
        exported = target_sdk is not None and target_sdk < 17
        source = "default"
    elif tag == "activity-alias" or has_filter:
        exported, source = has_filter, "intent-filter"
    else:
        exported, source = False, "default"

    launcher = any(
        "android.intent.action.MAIN" in f["actions"] and "android.intent.category.LAUNCHER" in f["categories"]
        for f in filters
    )
    item: dict[str, Any] = {
        "name": _qualify(_attr(comp, "name"), package),
        "exported": exported,
        "exported_source": source,
        "permission": _clip(_attr(comp, "permission"), 200),
        "enabled": _bool(_attr(comp, "enabled")),
        "launcher": launcher,
        "filters": filters,
    }
    if tag == "activity-alias":
        item["target"] = _qualify(_attr(comp, "targetActivity"), package)
    if tag == "provider":
        item["authorities"] = _clip(_attr(comp, "authorities"), 300)
        item["grant_uri_permissions"] = _bool(_attr(comp, "grantUriPermissions"))
        item["read_permission"] = _clip(_attr(comp, "readPermission"), 200)
        item["write_permission"] = _clip(_attr(comp, "writePermission"), 200)
    return item


def parse_manifest(apktool_dir: Path) -> dict[str, Any]:
    """Ringkas apktool_dir/AndroidManifest.xml (+ apktool.yml, res/values/strings.xml)."""
    root = _read_xml(apktool_dir / "AndroidManifest.xml")
    if root.tag != "manifest":
        raise ManifestError("elemen akar bukan <manifest>")
    if sum(1 for _ in root.iter()) > MAX_ELEMENTS:
        raise ManifestError("manifest memuat terlalu banyak elemen")

    yml = _read_apktool_yml(apktool_dir / "apktool.yml")
    package = _clip(root.get("package"), 200)

    uses_sdk = root.find("uses-sdk")
    min_sdk = _clip(_attr(uses_sdk, "minSdkVersion")) if uses_sdk is not None else None
    target_sdk = _clip(_attr(uses_sdk, "targetSdkVersion")) if uses_sdk is not None else None
    min_sdk = min_sdk or yml.get("minSdkVersion")
    target_sdk = target_sdk or yml.get("targetSdkVersion")
    target_int = int(target_sdk) if target_sdk and target_sdk.isdigit() else None

    permissions, seen = [], set()
    for el in root:
        if el.tag in {"uses-permission", "uses-permission-sdk-23"}:
            name = _clip(_attr(el, "name"), 200)
            if name and name not in seen and len(permissions) < 1000:
                seen.add(name)
                level = ("dangerous" if name in DANGEROUS_PERMISSIONS
                         else "special" if name in SPECIAL_PERMISSIONS else None)
                permissions.append({"name": name, "level": level})

    defined = [
        {"name": _clip(_attr(el, "name"), 200), "protection": _clip(_attr(el, "protectionLevel"), 80)}
        for el in root.findall("permission")[:200]
    ]
    features = [
        {"name": _clip(_attr(el, "name") or _attr(el, "glEsVersion"), 200),
         "required": _bool(_attr(el, "required"))}
        for el in root.findall("uses-feature")[:200]
    ]

    app_el = root.find("application")
    components: dict[str, list[dict[str, Any]]] = {t: [] for t in COMPONENT_TAGS}
    truncated = False
    flags: dict[str, Any] = {}
    label = app_class = None
    if app_el is not None:
        label = _resolve_label(_attr(app_el, "label"), apktool_dir / "res")
        app_class = _qualify(_attr(app_el, "name"), package)
        flags = {
            "debuggable": _bool(_attr(app_el, "debuggable")),
            "allow_backup": _bool(_attr(app_el, "allowBackup")),
            "uses_cleartext_traffic": _bool(_attr(app_el, "usesCleartextTraffic")),
            "test_only": _bool(_attr(root, "testOnly") or _attr(app_el, "testOnly")),
            "network_security_config": _clip(_attr(app_el, "networkSecurityConfig"), 200),
            "extract_native_libs": _bool(_attr(app_el, "extractNativeLibs")),
            "request_legacy_external_storage": _bool(_attr(app_el, "requestLegacyExternalStorage")),
        }
        count = 0
        for comp in app_el:
            if comp.tag in COMPONENT_TAGS:
                if count >= MAX_COMPONENTS:
                    truncated = True
                    break
                components[comp.tag].append(_component(comp.tag, comp, package, target_int))
                count += 1

    launcher = next(
        (c["name"] for t in ("activity", "activity-alias") for c in components[t] if c["launcher"]), None
    )
    warnings = ["Daftar komponen dipotong (terlalu banyak)."] if truncated else []

    return {
        "package": package,
        "app_label": label,
        "version_name": _clip(_attr(root, "versionName")) or yml.get("versionName"),
        "version_code": _clip(_attr(root, "versionCode")) or yml.get("versionCode"),
        "min_sdk": min_sdk,
        "target_sdk": target_sdk,
        "compile_sdk": _clip(_attr(root, "compileSdkVersion")),
        "application_class": app_class,
        "launcher": launcher,
        "flags": flags,
        "permissions": permissions,
        "defined_permissions": defined,
        "features": features,
        "components": components,
        "warnings": warnings,
    }
