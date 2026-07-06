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
    if results["executable"]:
     print(f"NX            : {protections.get('nx')}")
     print(f"ASLR          : {protections.get('aslr')}")
     print(f"PIE           : {protections.get('pie')}")
     print(f"RELRO         : {protections.get('relro')}")
     print(f"Canary        : {protections.get('canary')}")
    else:
        print("Not an executable binary.")
     
    print("\n Binary Analysis")
    print("─" * 62)
    if results["executable"]: 
     print(f"Packed        : {protections.get('packed')}")
     print(f"Packer        : {protections.get('packer_name','None')}")
     print(f"Linking       : {protections.get('linking')}")
     print(f"Stripped      : {protections.get('stripped')}")
    else:
     print("Not an executable binary.")

def kitty_meter(score):
    total = 30

    filled = int(score / 100 * total)

    bar = "█" * filled + "░" * (total - filled)

    print("\n😾 Kitty Suspicion")
    print("─" * 62)
    print(bar)
    print(f"{score}/100")



def verdict(score):
    print("\n🐈 Kitty Verdict")
    print("─" * 62)

    if score < 25:
        print("😺 Looks safe. Kitty is happy.")

    elif score < 50:
        print("😼 Kitty is curious.")

    elif score < 75:
        print("😾 Something smells suspicious.")

    else:
        print("🙀 Dangerous! Kitty refuses to touch it.")

def calculate_score(protections):

    score = 100

    if not protections.get("nx"):
        score -= 25

    if not protections.get("aslr"):
        score -= 20

    if not protections.get("pie"):
        score -= 15

    relro = protections.get("relro")

    if relro == "None":
        score -= 20
    elif relro == "Partial":
        score -= 10

    if not protections.get("canary"):
        score -= 15

    if protections.get("packed"):
        score += 10

    return max(0, min(score, 100))