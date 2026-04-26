from menu_ascii import print_banner, print_menu, print_scanning, clear
from scanner.scanner import run_scan
from scanner.manual import manual_path
from scanner.VM import run_vm_scan
from colorama import init, Fore, Style
import time


def main():
    while True:
        clear()
        print_banner()
        print_menu()

        choice = input("\n > ").strip()

        if choice == "1":
            run_vm_scan()
            print_scanning()
            run_scan()
            print(f"\n  {Fore.GREEN}Scan finished! Results in: 'Alt Detector.txt'{Style.RESET_ALL}\n")
            input("\n  Press Enter to return to menu...")

        elif choice == "2":
            manual_path()

        elif choice == "3":
            print(f"\n  {Fore.RED}Exiting..{Style.RESET_ALL}\n")
            break

        else:
            print(f"  {Fore.RED}[!] Invalid option, try again.{Style.RESET_ALL}")
            time.sleep(1)


if __name__ == "__main__":
    main()