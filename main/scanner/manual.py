import os
import re
import gzip
from pathlib import Path
from datetime import datetime
from colorama import Fore, Style

from menu_ascii import manual_ascii

MANUAL_OUTPUT_FILE = "Manual Path - Alt Scanner.txt"

MANUAL_HEADER = """\
Alt Detector | By Smooth
Github.com/Smoothzada/Minecraft-Alt-Detector
=================================================
"""

_SETTING_USER_RE      = re.compile(r"Setting user:\s+(\S+)", re.IGNORECASE)
_LC_SETTING_USER_RE   = re.compile(r"\[LC\]\s+Setting user:\s+(\S+)", re.IGNORECASE)
_LC_AUTH_RE           = re.compile(r"\[Authenticator\]\s+Creating Minecraft session for\s+(\S+)", re.IGNORECASE)
_ADDING_SESSION_RE    = re.compile(r"Adding session:\s+(\S+)", re.IGNORECASE)
_DISPLAY_NAME_RE      = re.compile(r"displayName=([^\s,]+)")
_CELESTIAL_LOADED_RE  = re.compile(r"\[LC Accounts\]\s+Loaded content for \[(\S+)\]", re.IGNORECASE)
_CELESTIAL_REFRESH_RE = re.compile(r"\[LC Accounts\]\s+Refreshing account:\s+(\S+)", re.IGNORECASE)

ALL_PATTERNS = [
    _SETTING_USER_RE,
    _LC_SETTING_USER_RE,
    _LC_AUTH_RE,
    _ADDING_SESSION_RE,
    _DISPLAY_NAME_RE,
    _CELESTIAL_LOADED_RE,
    _CELESTIAL_REFRESH_RE,
]


def _read_gz(path: Path) -> "list[str]":
    try:
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
            return f.readlines()
    except Exception:
        try:
            with gzip.open(path, "rt", encoding="iso-8859-1", errors="replace") as f:
                return f.readlines()
        except Exception:
            return []


def _read_log(path: Path) -> "list[str]":
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            return f.readlines()
    except OSError:
        return []


def _scan_lines(lines: "list[str]") -> "set[str]":
    nicks: set[str] = set()
    for line in lines:
        for pattern in ALL_PATTERNS:
            m = pattern.search(line)
            if m:
                nick = m.group(1).strip()
                if nick:
                    nicks.add(nick)
                break
    return nicks


def _has_valid_files(folder: Path) -> bool:
    for f in folder.iterdir():
        if f.is_file() and f.suffix in (".gz", ".log"):
            return True
    return False


def _scan_folder(folder: Path) -> "set[str]":
    nicks: set[str] = set()
    for f in folder.iterdir():
        if not f.is_file():
            continue
        if f.suffix == ".gz":
            nicks.update(_scan_lines(_read_gz(f)))
        elif f.suffix == ".log":
            nicks.update(_scan_lines(_read_log(f)))
    return nicks


def _write_manual_output(path_str: str, nicks: "set[str]") -> None:
    output_path = Path(MANUAL_OUTPUT_FILE)
    timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    with output_path.open("w", encoding="utf-8") as f:
        f.write(MANUAL_HEADER)
        f.write(f"Scan date: {timestamp}\n")
        f.write(f"Path: {path_str}\n")
        f.write("\nNicks:\n")
        if nicks:
            for nick in sorted(nicks):
                f.write(f"\t{nick}\n")
        else:
            f.write("\t[N/A]\n")
        f.write("\n=================================================\n")


def manual_path() -> bool:
    os.system("cls")
    manual_ascii()

    while True:
        print(f"\n  {Fore.CYAN}Enter the folder path to analyze{Style.RESET_ALL}")
        user_input = input("\n> ").strip().strip('"').strip("'")

        if user_input.lower() == "f":
            return

        folder = Path(user_input)

        if not folder.exists() or not folder.is_dir():
            print(f"\n  {Fore.RED}[!] Folder not found or invalid path.{Style.RESET_ALL}")
            import time
            time.sleep(2)
            os.system("cls")
            manual_ascii()
            continue

        if not _has_valid_files(folder):
            print(f"\n  {Fore.RED}[!] No .gz or .log files found in the specified folder.{Style.RESET_ALL}")
            import time
            time.sleep(2)
            os.system("cls")
            manual_ascii()
            continue

        print(f"\n  {Fore.YELLOW}[*] Scanning{Style.RESET_ALL}", end="", flush=True)
        import time
        for _ in range(3):
            time.sleep(0.4)
            print(f"{Fore.YELLOW}.{Style.RESET_ALL}", end="", flush=True)
        print()

        nicks = _scan_folder(folder)
        _write_manual_output(str(folder), nicks)

        print(f"\n  {Fore.GREEN}Scan finished! Results in: '{MANUAL_OUTPUT_FILE}'{Style.RESET_ALL}\n")
        input("\n  Press Enter to return to menu...")