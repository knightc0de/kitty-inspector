def print_report(file_name, results, protections):
    print(r"""
╔══════════════════════════════════════════════════════════════╗
║                  🐱 KITTY INSPECTOR                          ║
║             Curious Cats Catch Hidden Threats                ║
╚══════════════════════════════════════════════════════════════╝

          """)

    print("🐾 Target")
    print("─" * 62)
    print(f"File: {file_name}")
    print("\n🧬 Identity")
    print("─" * 62)
    print(f"Type          : {results['file_type']}")
    print(f"Architecture  : {results['architecture']}")
    print(f"Executable    : {'Yes' if results['executable'] else 'No'}")
    print(f"Encoding      : {results['encoding']}")
    print(f"Language      : {results['language']}")
          
          
        




print_report("uhwduw","whuhw","efhuwgfui")






