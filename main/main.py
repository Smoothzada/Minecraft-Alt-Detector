from menu_ascii import print_banner, print_menu, print_scanning, print_done, print_cancelled
from scanner.scanner import run_scan


def main():
    print_banner()
    print_menu()

    while True:
        choice = input("\n > Escolha uma opção: ").strip()

        if choice == "1":
            print_scanning()
            run_scan()
            print_done()
            break

        elif choice == "2":
            print_cancelled()
            break

        else:
            print("   [!] Opção inválida. Digite 1 ou 2.")


if __name__ == "__main__":
    main()