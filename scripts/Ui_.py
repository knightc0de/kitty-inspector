import time

from rich.console import Console
from rich.status import Status

console = Console()


def status(value):
    """Pretty colored status values."""

    if value is True:
        return "[bold green]✔ Yes[/]"

    if value is False:
        return "[bold red]✘ No[/]"

    if value == "Full":
        return "[bold green]Full[/]"

    if value == "Partial":
        return "[bold yellow]Partial[/]"

    if value == "None":
        return "[bold red]None[/]"

    if value is None:
        return "[dim]-[/]"

    return f"[cyan]{value}[/]"


def print_report(file_name, results, protections):

    console.print()

    console.print(
r"""
[bold cyan]
╔══════════════════════════════════════════════════════════════╗
║                    KITTY INSPECTOR                         ║
║             Curious Cats File Threats  Analyzer              ║
╚══════════════════════════════════════════════════════════════╝
[/]
"""
    )

    console.print("[bold magenta]🐾 Target[/]")
    console.print("[cyan]" + "─" * 62)

    console.print(f"[bold]File[/]          : [white]{file_name}[/]")

    with console.status(
        "[bold cyan]🐾 Kitty is investigating...",
        spinner="dots"
    ):
        time.sleep(1.4)

    console.print()

    console.print("[bold magenta]📂 File Information[/]")
    console.print("[cyan]" + "─" * 62)

    console.print(
        f"[bold]Type[/]          : [white]{results['file_type']}[/]"
    )

    console.print(
        f"[bold]Architecture[/]  : [white]{results['architecture']}[/]"
    )

    console.print(
        f"[bold]Executable[/]    : {status(results['executable'])}"
    )

    console.print(
        f"[bold]Encoding[/]      : [white]{results['encoding']}[/]"
    )

    console.print(
        f"[bold]Language[/]      : [white]{results['language']}[/]"
    )

    console.print()

    console.print("[bold magenta]  Security Protections[/]")
    console.print("[cyan]" + "─" * 62)

    if results["executable"]:

        console.print(f"[bold]NX[/]            : {status(protections.get('nx'))}")
        console.print(f"[bold]ASLR[/]          : {status(protections.get('aslr'))}")
        console.print(f"[bold]PIE[/]           : {status(protections.get('pie'))}")
        console.print(f"[bold]RELRO[/]         : {status(protections.get('relro'))}")
        console.print(f"[bold]Canary[/]        : {status(protections.get('canary'))}")

    else:

        console.print("[yellow]Not an executable binary.[/]")

    console.print()

    console.print("[bold magenta]  Binary Analysis[/]")
    console.print("[cyan]" + "─" * 62)

    if results["executable"]:

        console.print(
            f"[bold]Packed[/]        : {status(protections.get('packed'))}"
        )

        console.print(
            f"[bold]Packer[/]        : [cyan]{protections.get('packer_name','None')}[/]"
        )

        console.print(
            f"[bold]Linking[/]       : [cyan]{protections.get('linking')}[/]"
        )

        console.print(
            f"[bold]Stripped[/]      : [cyan]{protections.get('stripped')}[/]"
        )

    else:

        console.print("[yellow]Not an executable binary.[/]")


def kitty_meter(score):
    """Display a colored Kitty suspicion meter."""

    total = 30
    filled = int(score / 100 * total)

    bar = "█" * filled + "░" * (total - filled)

    if score >= 75:
        color = "green"
        face = "😺"
        level = "SAFE"

    elif score >= 50:
        color = "yellow"
        face = "😼"
        level = "CAUTION"

    elif score >= 25:
        color = "dark_orange"
        face = "😾"
        level = "SUSPICIOUS"

    else:
        color = "red"
        face = "🙀"
        level = "DANGEROUS"

    console.print()
    console.print("[bold magenta]😾 Kitty Suspicion[/]")
    console.print("[cyan]" + "─" * 62)

    console.print(f"[{color}]{bar}[/]")
    console.print(
        f"{face}  [bold {color}]{score}/100[/]   [{color}]{level}[/]"
    )


def verdict(score):
    """Display Kitty's final verdict."""

    console.print()
    console.print("[bold magenta]🐈 Kitty Verdict[/]")
    console.print("[cyan]" + "─" * 62)

    if score >= 75:
        console.print(
            "[bold green]😺 Kitty purrs... This binary looks well protected.[/]"
        )

    elif score >= 50:
        console.print(
            "[bold yellow]😼 Kitty is curious. A few weak spots were found.[/]"
        )

    elif score >= 25:
        console.print(
            "[bold dark_orange]😾 Kitty smells something suspicious. Inspect carefully.[/]"
        )

    else:
        console.print(
            "[bold red]🙀 Kitty refuses to touch this binary! High security risk detected.[/]"
        )


def calculate_score(protections):
    """
    Calculate a security score (0–100).
    Higher score = Better protected binary.
    """

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

    # Packed binaries are slightly more suspicious
    if protections.get("packed"):
        score -= 10

    return max(0, min(score, 100))
