import os
import json
import gzip
import re
from pathlib import Path
from datetime import datetime

"""
Detections:
  1.  usercache.json
  2.  launcher_accounts_microsoft_store.json
  3.  .minecraft/logs/*.gz
  4.  .minecraft/config/ias.json          (In-Game Account Switcher)
  5.  .lunarclient/logs/game/*.log        (Lunar Client - game logs)
  6.  .lunarclient/logs/launcher/main.log (Lunar Client - launcher)
  7.  .lunarclient/offline/multiver/logs  (Lunar Client - offline)
  8.  .minecraft/logs/blclient/minecraft  (Badlion - Setting user)
  9.  .minecraft/logs/blclient/minecraft  (Badlion - Adding session)
  10. .tlauncher/logs/tlauncher/*.log      (TLauncher)
  11. .cubewhy/lunarcn/game/logs           (CubeWhy)
  12. .weave/CrackedAccount/account.json   (Weave Cracked)
  13. .minecraft/feather/logs/latest.log   (Feather Client)
  14. %APPDATA%/celestial/game/logs          (Celestial Client)
"""



# Cabeçalho do arquivo de saída
HEADER = """\
Alt Detector | By Smooth
Github.com/smoothzada/alt-detector
=================================================
"""

OUTPUT_FILE = "Alt Detector.txt"

IAS_TYPE_LABEL = {
    "ias:offline":   "Pirata",
    "ias:microsoft": "Original",
}

_SETTING_USER_RE      = re.compile(r"Setting user:\s+(\S+)", re.IGNORECASE)
_LC_SETTING_USER_RE   = re.compile(r"\[LC\]\s+Setting user:\s+(\S+)", re.IGNORECASE)
_LC_AUTH_RE           = re.compile(r"\[Authenticator\]\s+Creating Minecraft session for\s+(\S+)", re.IGNORECASE)
_ADDING_SESSION_RE    = re.compile(r"Adding session:\s+(\S+)", re.IGNORECASE)
_DISPLAY_NAME_RE      = re.compile(r"displayName=([^\s,]+)")
_PLAYER_FILTER_RE     = re.compile(r"^Player\d+$", re.IGNORECASE)
_PLAYER3_FILTER_RE    = re.compile(r"^Player\d{3}$", re.IGNORECASE)
_CELESTIAL_LOADED_RE  = re.compile(r"\[LC Accounts\]\s+Loaded content for \[(\S+)\]", re.IGNORECASE)
_CELESTIAL_REFRESH_RE = re.compile(r"\[LC Accounts\]\s+Refreshing account:\s+(\S+)", re.IGNORECASE)

def get_minecraft_path() -> "Path | None":
    appdata = os.getenv("APPDATA")
    if not appdata:
        return None
    path = Path(appdata) / ".minecraft"
    return path if path.is_dir() else None

def get_userprofile_path() -> "Path | None":
    profile = os.getenv("USERPROFILE")
    if not profile:
        return None
    path = Path(profile)
    return path if path.is_dir() else None


# Helpers de leitura

def _read_gz(path: Path, encoding: str = "utf-8") -> "list[str]":
    try:
        with gzip.open(path, "rt", encoding=encoding, errors="replace") as f:
            return f.readlines()
    except (OSError, gzip.BadGzipFile, EOFError):
        return []


def _read_log(path: Path, encoding: str = "utf-8") -> "list[str]":
    try:
        with path.open("r", encoding=encoding, errors="replace") as f:
            return f.readlines()
    except OSError:
        return []


def _scan_lines(lines: "list[str]", pattern: re.Pattern, exclude: "re.Pattern | None" = None) -> "set[str]":
    nicks: set[str] = set()
    for line in lines:
        m = pattern.search(line)
        if m:
            nick = m.group(1).strip()
            if nick and (exclude is None or not exclude.match(nick)):
                nicks.add(nick)
    return nicks


# Formatação de seções

def format_simple_section(title: str, nicks: "set[str]") -> str:
    lines = [f"\n[{title}]", "Nicks:"]
    if nicks:
        for nick in sorted(nicks):
            lines.append(f"\t{nick}")
    else:
        lines.append("\t[N/A]")
    return "\n".join(lines)


def format_labeled_section(title: str, entries: "list[tuple[str, str]]") -> str:
    lines = [f"\n[{title}]", "Nicks:"]
    if entries:
        for nick, label in sorted(entries, key=lambda x: x[0].lower()):
            lines.append(f"\t{nick} | {label}")
    else:
        lines.append("\t[N/A]")
    return "\n".join(lines)


# Fonte 1 — usercache.json

def scan_usercache(minecraft_path: Path) -> "set[str] | None":
    cache_file = minecraft_path / "usercache.json"
    if not cache_file.is_file():
        return None

    nicks: set[str] = set()
    try:
        with cache_file.open("r", encoding="utf-8") as f:
            data = json.load(f)
        for entry in data:
            name = entry.get("name", "").strip()
            if name:
                nicks.add(name)
    except (json.JSONDecodeError, OSError):
        pass

    return nicks


# Fonte 2 — launcher_accounts_microsoft_store.json

def scan_launcher_accounts(minecraft_path: Path) -> "set[str] | None":
    launcher_file = minecraft_path / "launcher_accounts_microsoft_store.json"
    if not launcher_file.is_file():
        return None

    nicks: set[str] = set()
    try:
        with launcher_file.open("r", encoding="utf-8") as f:
            data = json.load(f)
        nicks.update(_extract_names_recursive(data))
    except (json.JSONDecodeError, OSError):
        pass

    return nicks


def _extract_names_recursive(obj) -> "set[str]":
    found: set[str] = set()
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key == "name" and isinstance(value, str) and value.strip():
                found.add(value.strip())
            else:
                found.update(_extract_names_recursive(value))
    elif isinstance(obj, list):
        for item in obj:
            found.update(_extract_names_recursive(item))
    return found


# Fonte 3 — .minecraft/logs/*.gz

def scan_logs_gz(minecraft_path: Path) -> "set[str] | None":
    logs_dir = minecraft_path / "logs"
    if not logs_dir.is_dir():
        return None

    nicks: set[str] = set()
    for gz_file in logs_dir.iterdir():
        if gz_file.is_file() and gz_file.suffix == ".gz":
            nicks.update(_scan_lines(_read_gz(gz_file), _SETTING_USER_RE))

    return nicks


# Fonte 4 — .minecraft/config/ias.json


def scan_ias(minecraft_path: Path) -> "list[tuple[str, str]] | None":
    
    ias_file = minecraft_path / "config" / "ias.json"
    if not ias_file.is_file():
        return None

    entries: list[tuple[str, str]] = []
    seen: set[str] = set()

    try:
        with ias_file.open("r", encoding="utf-8") as f:
            data = json.load(f)

        if isinstance(data, list):
            account_list = data
        elif isinstance(data, dict):
            account_list = data.get("accounts") or _find_account_list(data)
        else:
            account_list = []

        for entry in account_list:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name", "").strip()
            acc_type = entry.get("type", "").strip().lower()
            if not name or name in seen:
                continue
            seen.add(name)
            label = IAS_TYPE_LABEL.get(acc_type, "Desconhecido")
            entries.append((name, label))

    except (json.JSONDecodeError, OSError):
        pass

    return entries


def _find_account_list(obj: dict) -> list:
    for value in obj.values():
        if isinstance(value, list):
            if any(isinstance(i, dict) and "name" in i and "type" in i for i in value):
                return value
        elif isinstance(value, dict):
            result = _find_account_list(value)
            if result:
                return result
    return []


# Fonte 5 — Lunar Client (game logs)

def scan_lunar_game_logs(lunar_path: Path) -> "set[str] | None":
    logs_dir = lunar_path / "logs" / "game"
    if not logs_dir.is_dir():
        return None

    nicks: set[str] = set()
    for log_file in logs_dir.iterdir():
        if log_file.is_file() and log_file.suffix == ".log":
            nicks.update(_scan_lines(_read_log(log_file), _LC_SETTING_USER_RE))

    return nicks


# Fonte 6 — Lunar Client (launcher log)

def scan_lunar_launcher_log(lunar_path: Path) -> "set[str] | None":
    log_file = lunar_path / "logs" / "launcher" / "main.log"
    if not log_file.is_file():
        return None

    return _scan_lines(_read_log(log_file), _LC_AUTH_RE)


# Fonte 7 — Lunar Client Offline


def scan_lunar_offline(lunar_path: Path) -> "set[str] | None":
    logs_dir = lunar_path / "offline" / "multiver" / "logs"
    if not logs_dir.is_dir():
        return None

    nicks: set[str] = set()

    for gz_file in logs_dir.iterdir():
        if gz_file.is_file() and gz_file.name.endswith(".log.gz"):
            nicks.update(_scan_lines(
                _read_gz(gz_file, encoding="iso-8859-1"),
                _SETTING_USER_RE,
                exclude=_PLAYER_FILTER_RE,
            ))

    # latest.log
    latest = logs_dir / "latest.log"
    if latest.is_file():
        nicks.update(_scan_lines(
            _read_log(latest),
            _SETTING_USER_RE,
            exclude=_PLAYER_FILTER_RE,
        ))

    return nicks

# Fonte 8 — Badlion Setting user

def scan_badlion_setting_user(minecraft_path: Path) -> "set[str] | None":
    logs_dir = minecraft_path / "logs" / "blclient" / "minecraft"
    if not logs_dir.is_dir():
        return None

    nicks: set[str] = set()
    for f in logs_dir.iterdir():
        if not f.is_file():
            continue
        lines = _read_gz(f, "iso-8859-1") if f.suffix == ".gz" else _read_log(f)
        nicks.update(_scan_lines(lines, _SETTING_USER_RE))

    return nicks


# Fonte 9 — Badlion Adding session

def scan_badlion_adding_session(minecraft_path: Path) -> "set[str] | None":
    logs_dir = minecraft_path / "logs" / "blclient" / "minecraft"
    if not logs_dir.is_dir():
        return None

    nicks: set[str] = set()
    for f in logs_dir.iterdir():
        if not f.is_file():
            continue
        lines = _read_gz(f, "iso-8859-1") if f.suffix == ".gz" else _read_log(f)
        nicks.update(_scan_lines(lines, _ADDING_SESSION_RE))

    return nicks


# Fonte 10 — TLauncher

def scan_tlauncher(appdata_path: Path) -> "set[str] | None":
    logs_dir = appdata_path / ".tlauncher" / "logs" / "tlauncher"
    if not logs_dir.is_dir():
        return None

    nicks: set[str] = set()
    for log_file in logs_dir.iterdir():
        if log_file.is_file() and log_file.suffix == ".log":
            nicks.update(_scan_lines(_read_log(log_file), _DISPLAY_NAME_RE))

    return nicks
# Fonte 11 — CubeWhy

def scan_cubewhy(userprofile_path: Path) -> "set[str] | None":
    logs_dir = userprofile_path / ".cubewhy" / "lunarcn" / "game" / "logs"
    if not logs_dir.is_dir():
        return None

    nicks: set[str] = set()

    for gz_file in logs_dir.iterdir():
        if gz_file.is_file() and gz_file.suffix == ".gz":
            nicks.update(_scan_lines(
                _read_gz(gz_file),
                _SETTING_USER_RE,
                exclude=_PLAYER3_FILTER_RE,
            ))

    latest = logs_dir / "latest.log"
    if latest.is_file():
        nicks.update(_scan_lines(
            _read_log(latest),
            _SETTING_USER_RE,
            exclude=_PLAYER3_FILTER_RE,
        ))

    return nicks

# Fonte 12 — Weave Cracked Accounts

def scan_weave_cracked(userprofile_path: Path) -> "set[str] | None":
    account_file = userprofile_path / ".weave" / "CrackedAccount" / "account.json"
    if not account_file.is_file():
        return None

    nicks: set[str] = set()
    try:
        with account_file.open("r", encoding="utf-8") as f:
            data = json.load(f)
        name = data.get("crackedAccountName", "").strip()
        if name:
            nicks.add(name)
    except (json.JSONDecodeError, OSError):
        pass

    return nicks


# Fonte 13 — Feather Client

def scan_feather(minecraft_path: Path) -> "set[str] | None":
    log_file = minecraft_path / "feather" / "logs" / "latest.log"
    if not log_file.is_file():
        return None

    return _scan_lines(_read_log(log_file), _SETTING_USER_RE)

# Fonte 14 — Celestial Client

def scan_celestial(appdata_path: Path) -> "set[str] | None":
    logs_dir = appdata_path / "celestial" / "game" / "logs"
    if not logs_dir.is_dir():
        return None

    nicks: set[str] = set()
    for log_file in logs_dir.iterdir():
        if log_file.is_file() and log_file.suffix == ".log":
            lines = _read_log(log_file)
            nicks.update(_scan_lines(lines, _CELESTIAL_LOADED_RE))
            nicks.update(_scan_lines(lines, _CELESTIAL_REFRESH_RE))

    return nicks

# Escrita do arquivo de saída

def write_output(
    simple_sections: "list[tuple[str, set[str] | None]]",
    labeled_sections: "list[tuple[str, list[tuple[str, str]] | None]]",
) -> None:

    output_path = Path(OUTPUT_FILE)
    timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    with output_path.open("w", encoding="utf-8") as f:
        f.write(HEADER)
        f.write(f"Gerado em: {timestamp}\n")

        for title, nicks in simple_sections:
            if nicks is None:
                continue
            f.write(format_simple_section(title, nicks))
            f.write("\n")

        for title, entries in labeled_sections:
            if entries is None:
                continue
            f.write(format_labeled_section(title, entries))
            f.write("\n")

        f.write("\n=================================================\n")

# Entry point principal

def run_scan() -> None:
    minecraft_path   = get_minecraft_path()
    userprofile_path = get_userprofile_path()

    appdata = os.getenv("APPDATA")
    appdata_path = Path(appdata) if appdata else None

    lunar_path = (userprofile_path / ".lunarclient") if userprofile_path else None
    lunar_path = lunar_path if (lunar_path and lunar_path.is_dir()) else None

    simple_sections: list[tuple[str, "set[str] | None"]] = []
    labeled_sections: list[tuple[str, "list[tuple[str,str]] | None"]] = []

    if minecraft_path:
        simple_sections += [
            ("usercache.json",                          scan_usercache(minecraft_path)),
            ("launcher_accounts_microsoft_store.json",  scan_launcher_accounts(minecraft_path)),
            ("Minecraft Logs (.gz)",                    scan_logs_gz(minecraft_path)),
            ("Badlion Client - Setting user",           scan_badlion_setting_user(minecraft_path)),
            ("Badlion Client - Adding session",         scan_badlion_adding_session(minecraft_path)),
            ("Feather Client",                          scan_feather(minecraft_path)),
        ]
        labeled_sections += [
            ("In-Game Account Switcher",                scan_ias(minecraft_path)),
        ]

    if lunar_path:
        simple_sections += [
            ("Lunar Client - Game Logs",                scan_lunar_game_logs(lunar_path)),
            ("Lunar Client - Launcher",                 scan_lunar_launcher_log(lunar_path)),
            ("Lunar Client - Offline",                  scan_lunar_offline(lunar_path)),
        ]

    if appdata_path:
        simple_sections += [
            ("TLauncher",                               scan_tlauncher(appdata_path)),
            ("Celestial Client",                        scan_celestial(appdata_path)),
        ]

    if userprofile_path:
        simple_sections += [
            ("CubeWhy",                                 scan_cubewhy(userprofile_path)),
            ("Weave Cracked Accounts",                  scan_weave_cracked(userprofile_path)),
        ]

    write_output(simple_sections, labeled_sections)