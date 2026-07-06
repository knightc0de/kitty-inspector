def print_report(file_name, results, protections):
    print(r"""
╔══════════════════════════════════════════════════════════════╗
║                  🐱 KITTY INSPECTOR                         ║
║             Curious Cats Catch Hidden Threats               ║
╚══════════════════════════════════════════════════════════════╝
""")

    print("🐾 Target")
    print("─" * 62)
    print(f"File          : {file_name}")

    print("\n File_info ")
    print("─" * 62)
    print(f"Type          : {results['file_type']}")
    print(f"Architecture  : {results['architecture']}")
    print(f"Executable    : {'Yes' if results['executable'] else 'No'}")
    print(f"Encoding      : {results['encoding']}")
    print(f"Language      : {results['language']}")

    print("\n🛡 Security Methods")
    print("─" * 62)
    print(f"NX            : {protections.get('nx')}")
    print(f"ASLR          : {protections.get('aslr')}")
    print(f"PIE           : {protections.get('pie')}")
    print(f"RELRO         : {protections.get('relro')}")
    print(f"Canary        : {protections.get('canary')}")

    print("\n Binary Analysis")
    print("─" * 62)
    print(f"Packed        : {protections.get('packed')}")
    print(f"Packer        : {protections.get('packer_name','None')}")
    print(f"Linking       : {protections.get('linking')}")
    print(f"Stripped      : {protections.get('stripped')}")