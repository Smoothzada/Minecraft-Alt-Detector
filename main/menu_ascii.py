from colorama import init, Fore, Style
import os
def print_banner():
    print(f"""{Fore.CYAN} 
  █████╗ ██╗  ████████╗    ██████╗ ███████╗████████╗███████╗ ██████╗████████╗ ██████╗ ██████╗ 
 ██╔══██╗██║  ╚══██╔══╝    ██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
 ███████║██║     ██║       ██║  ██║█████╗     ██║   █████╗  ██║        ██║   ██║   ██║██████╔╝
 ██╔══██║██║     ██║       ██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗
 ██║  ██║███████╗██║       ██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
 ╚═╝  ╚═╝╚══════╝╚═╝       ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
    by Smooth | Github.com/Smoothzada
{Style.RESET_ALL}
    """)


def print_menu():
    print("  [1] Run Alt-Scanner")
    print("  [2] Exit")


def print_scanning():
    print(f"\n  {Fore.YELLOW}[*] Scanning{Style.RESET_ALL}", end="", flush=True)
    import time
    for _ in range(3):
        time.sleep(0.5)
        print(f"{Fore.YELLOW}.{Style.RESET_ALL}", end="", flush=True)
    print("\n")


def print_done():
    print(f"\n  {Fore.GREEN}Scan finished! Results in: 'Alt Detector.txt'{Style.RESET_ALL}\n")


def print_cancelled():
    print(f"\n  {Fore.RED}Exiting..{Style.RESET_ALL}\n")

def clear():
    os.system("cls")