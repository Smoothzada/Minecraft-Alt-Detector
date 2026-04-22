from menu_ascii import print_banner, print_menu, print_scanning, clear
from scanner.scanner import run_scan
from scanner.manual import manual_path
from colorama import init, Fore, Style


def main():
    while True:
        clear()
        print_banner()
        print_menu()

        choice = input("\n > ").strip()

        if choice == "1":
            print_scanning()
            run_scan()
            print(f"\n  {Fore.GREEN}Scan finished! Results in: 'Alt Detector.txt'{Style.RESET_ALL}\n")
            input("\n  Press Enter to exit...")
            break

        elif choice == "2":
            went_back = manual_path()
            if went_back:
                continue
            break

        elif choice == "3":
            print(f"\n  {Fore.RED}Exiting..{Style.RESET_ALL}\n")
            break

        else:
            print(f"  {Fore.RED}[!] Invalid option, try again.{Style.RESET_ALL}")
            import time
            time.sleep(1)


if __name__ == "__main__":
    main()