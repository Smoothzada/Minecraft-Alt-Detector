import os
import platform
import subprocess
import winreg
from pathlib import Path
from datetime import datetime
from colorama import Fore, Style

_VM_ENV_STRINGS = [
    "virtualbox", "vmware", "vbox", "qemu",
    "hyperv", "hyper-v", "xen", "parallels",
    "virtual", "sandbox",
]

_VM_ENV_KEY_WHITELIST = [
    "VBOX_HWVIRTEX_IGNORE_SVM_IN_USE",
    "VBOX_MSI_INSTALL_PATH",
    "VBOX_INSTALL_PATH",
]

_VM_HOSTNAME_STRINGS = [
    "virtualbox", "vmware", "vbox", "sandbox",
    "qemu", "hyperv", "xen",
]

_VM_MAC_PREFIXES = [
    "08:00:27",  # VirtualBox
    "00:0c:29",  # VMware
    "00:50:56",  # VMware
    "00:05:69",  # VMware
    "00:1c:14",  # VMware
    "00:15:5d",  # Hyper-V
    "52:54:00",  # QEMU / KVM
    "00:16:3e",  # Xen
]

_VM_PROCESSES = [
    "vboxservice.exe", "vboxtray.exe",
    "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
    "vmsrvc.exe", "vmusrvc.exe",
    "xenservice.exe", "qemu-ga.exe",
    "prl_tools.exe", "prl_cc.exe",
]

_VM_REG_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Oracle\VirtualBox Guest Additions"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\VMware, Inc.\VMware Tools"),
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\VBoxGuest"),
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\vmhgfs"),
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\VMMEMCTL"),
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\vmmouse"),
    (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\ACPI\DSDT\VBOX__"),
    (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\ACPI\FADT\VBOX__"),
    (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\ACPI\RSDT\VBOX__"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters"),
]

DEBUG_OUTPUT_FILE = "VM_debug.txt"

# stage 1

def _stage1_env() -> "list[str]":
    hits = []
    for key, value in os.environ.items():
        if key in _VM_ENV_KEY_WHITELIST:
            continue
        combined = (key + value).lower()
        for sig in _VM_ENV_STRINGS:
            if sig in combined:
                hits.append(f"[Stage 1 - ENV] Key='{key}' Value='{value}' matched '{sig}'")
                break
    return hits


def _stage1_hostname() -> "list[str]":
    hits = []
    hostname = platform.node()
    username = os.getenv("USERNAME", "")
    for sig in _VM_HOSTNAME_STRINGS:
        if sig in hostname.lower():
            hits.append(f"[Stage 1 - HOSTNAME] hostname='{hostname}' matched '{sig}'")
        if sig in username.lower():
            hits.append(f"[Stage 1 - USERNAME] username='{username}' matched '{sig}'")
    return hits


def stage1() -> "list[str]":
    return _stage1_env() + _stage1_hostname()


# stage 2

def _stage2_mac() -> "list[str]":
    hits = []
    try:
        result = subprocess.check_output(
            ["getmac", "/fo", "csv", "/nh"],
            stderr=subprocess.DEVNULL,
            timeout=5,
        ).decode(errors="replace")
        for line in result.splitlines():
            for prefix in _VM_MAC_PREFIXES:
                if prefix.lower() in line.lower():
                    hits.append(f"[Stage 2 - MAC] line='{line.strip()}' matched prefix '{prefix}'")
    except Exception:
        pass
    return hits


def _stage2_processes() -> "list[str]":
    hits = []
    try:
        result = subprocess.check_output(
            ["tasklist", "/fo", "csv", "/nh"],
            stderr=subprocess.DEVNULL,
            timeout=5,
        ).decode(errors="replace")
        for line in result.splitlines():
            for proc in _VM_PROCESSES:
                if proc.lower() in line.lower():
                    hits.append(f"[Stage 2 - PROCESS] matched '{proc}'")
    except Exception:
        pass
    return hits


def _stage2_registry() -> "list[str]":
    hits = []
    for hive, path in _VM_REG_KEYS:
        try:
            key = winreg.OpenKey(hive, path)
            winreg.CloseKey(key)
            hits.append(f"[Stage 2 - REGISTRY] found key '{path}'")
        except OSError:
            pass
    return hits


def stage2() -> "list[str]":
    return _stage2_mac() + _stage2_processes() + _stage2_registry()


# output

def _write_debug(hits: "list[str]") -> None:
    output_path = Path(DEBUG_OUTPUT_FILE)
    timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    with output_path.open("w", encoding="utf-8") as f:
        f.write("Alt Detector | VM Debug Log\n")
        f.write("Github.com/Smoothzada/Minecraft-Alt-Detector\n")
        f.write("=================================================\n")
        f.write(f"Scan date: {timestamp}\n\n")
        f.write("Triggers found:\n")
        for hit in hits:
            f.write(f"  {hit}\n")
        f.write("\n=================================================\n")



def run_vm_scan() -> bool:

    print(f"\n  {Fore.YELLOW}[*] Searching for VM's{Style.RESET_ALL}", end="", flush=True)

    import time
    for _ in range(3):
        time.sleep(0.4)
        print(f"{Fore.YELLOW}.{Style.RESET_ALL}", end="", flush=True)
    print()

    hits = stage1() + stage2()

    if hits:
        print(f"\n  {Fore.RED}[!] The player has been found using a Virtual Machine{Style.RESET_ALL}")
        _write_debug(hits)
        print(f"  {Fore.RED}[!] Debug saved to: '{DEBUG_OUTPUT_FILE}'{Style.RESET_ALL}")
        return True
    else:
        print(f"\n  {Fore.GREEN}[*] Clean{Style.RESET_ALL}")
        return False