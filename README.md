# 🐱 Kitty Inspector
![](/scripts/img0.png)

# About

> **Curious Cats Catch Hidden Threats**

Kitty Inspector is a cross-platform binary and file analysis tool written in Python. It helps security researchers, reverse engineers, students, and developers quickly identify file formats, executable types, binary security protections, packers, and programming languages from a single command-line interface.

---

###  File Type Detection

* Detects source code files 
* Uses a YAML-based extension database for easy customization
* Falls back to binary signature detection 

###  Binary Analysis

Supports detection of:

* Windows PE Executables
* Linux ELF Binaries
* macOS Mach-O Executables
* Android APK Packages
* Windows DLLs
* Linux Shared Objects (.so)

###  Archive Detection

Recognizes common archive formats:

* ZIP
* RAR
* 7-Zip
* TAR
* GZIP
* BZIP2

###  Binary Protection Detection

* NX (No Execute)
* ASLR
* PIE
* RELRO
* Stack Canary
* Static / Dynamic Linking
* Stripped Symbols

###  Packer Detection

Detects common executable packers including:

* UPX
* Themida
* VMProtect
* ASPack
* MPRESS
* PECompact

###  Language Detection
Examples include:

* Python
* C
* C++
* Java
* JavaScript
* PHP
* HTML

## Security Score

- Calculates an overall binary security score based on detected protections
---



##  Architecture
```mermaid
flowchart LR

    U([User])

    CLI["CLI Interface
    (argparse)"]

    KI["Kitty Investigator"]

    FT["File Type Detection"]

    BD["Binary Detection"]

    LD["Language Detection"]

    EN["Encoding Detection"]

    PD["Protection Detection"]

    PK["Packer Detection"]

    SCORE["Security Scoring"]

    UI["Rich Terminal UI"]

    U --> CLI
    CLI --> KI

    KI --> FT
    KI --> BD
    KI --> LD
    KI --> EN

    BD --> PD
    PD --> PK
    PK --> SCORE

    FT --> UI
    BD --> UI
    LD --> UI
    EN --> UI
    SCORE --> UI
```

---

## Detection Workflow

```mermaid
flowchart TD

A([Input File])

A --> B[Read CLI Arguments]

B --> C[Initialize Kitty Investigator]

C --> D[Detect File Extension]

D --> E[YAML File Type Database]

E --> F{Extension Found?}

F -->|Yes| G[Assign Friendly File Type]

F -->|No| H[filetype Library Detection]

H --> I[Binary Signature Detection]

G --> I

I --> J[Detect Architecture]

J --> K[Detect Encoding]

K --> L[Detect Language]

L --> M{Executable?}

M -->|No| N[Generate File Report]

M -->|Yes| O[LIEF Protection Analysis]

O --> P[Raw Byte Analysis]

P --> Q[Packer Detection]

Q --> R[Security Score]

R --> S[Generate Rich Report]

S --> T([End])

N --> T
```

##  Installation

Clone the repository:

```bash
git clone https://github.com/knightc0de/kitty-inspector.git
cd kitty-inspector
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it:

**Windows**

```bash
.venv\Scripts\activate
```

**Linux/macOS**

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

##  Requirements

* Python 3.10+
* LIEF
* Rich
* PyYAML
* Pygments
* filetype
* colorama

---

## 💻 Usage

Analyze any file:

```bash
python kitty_investigator.py sample.exe
```

Analyze non-executable files:

```bash
python kitty_investigator.py README.md
```

---


## 🤝 Contributing

Contributions are welcome.

If you have ideas, improvements, or bug fixes:

1. Fork the repository
2. Create a new feature branch
3. Commit your changes
4. Submit a Pull Request

---

## 📄 License

This project is licensed under the MIT License.

---

## 👨‍💻 Author

**Puneet Singh**

Cybersecurity Enthusiast • Programmer • Reverse Engineering Learner

GitHub: https://github.com/knightc0de

---

## ⭐ Support

If you found Kitty Inspector useful, consider giving the repository a ⭐ on GitHub. It helps the project reach more developers and security enthusiasts.

---


