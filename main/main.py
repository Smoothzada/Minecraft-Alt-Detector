from menu_ascii import print_banner, print_menu, print_scanning, clear
from scanner.scanner import run_scan
from colorama import init, Fore, Style


def main():
    clear()
    print_banner()
    print_menu()

    while True:
        choice = input("\n > ").strip()

        if choice == "1":
            print_scanning()
            run_scan()
            print(f"\n  {Fore.GREEN}Scan finished! Results in: 'Alt Detector.txt'{Style.RESET_ALL}\n")
            input("\n  Press Enter to exit...")
            break

        elif choice == "2":
            print(f"\n  {Fore.RED}Exiting..{Style.RESET_ALL}\n")
            break
            

        else:
            print(f" {Fore.RED}  [!] invalid option, try again.{Style.RESET_ALL}")


if __name__ == "__main__":
    main()