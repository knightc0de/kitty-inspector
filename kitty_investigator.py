from argparse import FileType
import struct 
from  pathlib import Path 
import zipfile
import re 

results = { "file_type" : "Unknown",
           "architecture" : "Unknown", 
           "executable"   :  False,
           "encoding"     :  "Unknown",
           "language"     : "Unknown",}

FILE_TYPES = {
    ".py": "Python Script",
    ".c": "C Source File",
    ".cpp": "C++ Source File",
    ".cc": "C++ Source File",
    ".cxx": "C++ Source File",
    ".h": "C/C++ Header File",
    ".hpp": "C++ Header File",
    ".js": "JavaScript File",
    ".ts": "TypeScript File",
    ".java": "Java Source File",
    ".php": "PHP Script",
    ".html": "HTML Document",
    ".htm": "HTML Document",
    ".css": "CSS Stylesheet",
    ".xml": "XML Document",
    ".json": "JSON File",
    ".yaml": "YAML File",
    ".yml": "YAML File",
    ".ini": "INI Configuration File",
    ".cfg": "Configuration File",
    ".conf": "Configuration File",
    ".sh": "Shell Script",
    ".bash": "Shell Script",
    ".zsh": "Shell Script",
    ".ps1": "PowerShell Script",
    ".bat": "Batch Script",
    ".cmd": "Command Script",
    ".go": "Go Source File",
    ".rs": "Rust Source File",
    ".swift": "Swift Source File",
    ".kt": "Kotlin Source File",
    ".rb": "Ruby Script",
    ".pl": "Perl Script",
    ".lua": "Lua Script",
    ".sql": "SQL Script",
    ".md": "Markdown Document",
    ".txt": "Text File",
}

class Kitty_investigator():
      def __init__(self,path):
            self.path = Path(path)
            self.results = results.copy()
    
      def file_type(self):
         try:
           ext = self.path.suffix.lower()

           self.results["file_type"] = FILE_TYPES.get(ext,f"Unknown ({ext})" if ext else "Unknown")

         except Exception as e:
             print(f"ERROR: {e}")
             self.results["file_type"] = "Unknown"

         return self.results

# ;; windows PE ;;     
      def detect_binary(self):
          with open(self.path,"rb") as file :
               header = file.read(64)

          if header[:2] == b"MZ":
             self.results["file_type"]  = "Windows PE" 
             self.results["executable"] = True  
             with open(self.path,"rb") as file:
                 data = file.read()
                 offset = struct.unpack("<I",data[0x3c:0x40])[0]
                 if data[offset:offset+4] == b"PE\0\0":
                     machine = struct.unpack("<H", data[offset+4:offset+6])[0]
                     if machine == 0x14c:
                        self.results["architecture"] = "32-bit (x86)"
                     elif  machine == 0x8664:
                         self.results["architecture"] = "64-bit (x64)"
                     else:
                         self.results["architecture"] = f"Unknown (machine={hex(machine)})"      
             
 # ;; Linux ELF ;; 
          elif   header[:4] == b"\x7fELF":
                 self.results["file_type"]  = "Linux ElF Executable"
                 self.results["executable"] = True 
                 bit_format = header[4]
                 self.results["architecture"] = "32-bit" if bit_format  == 1 else "64-bit"
# ;; MacOS ;;  
          elif  header[:4] in [
                b"\xFE\xED\xFA\xCE" , b"\xCE\xFA\xED\xFE",
                b"\xFE\xED\xFA\xCF" , b"\xCF\xFA\xED\xFE" ]:
                self.results["file_type"] = "macOs Mach-O Exceutable"
                self.results["exceutable"]  = True 
                self.results["architecture"] = "64-bit" if header[:4] in [b"\xFE\xED\xFA\xCF", b"\xCF\xFA\xED\xFE"] else "32-bit"
 
        

 # ;; Android APK  ;;
          elif zipfile.is_zipfile(self.path):
            try:
                with zipfile.ZipFile(self.path, "r") as z:
                    if "AndroidManifest.xml" in z.namelist():
                        self.results["file_type"] = "Android APK"
                        self.results["executable"] = False
                        self.results["language"] = "Android Package"
            except Exception:
                pass

           
# ;; Linux Shared Object (.so) ;;
          elif self.path.suffix.lower() == ".so": 
             if header[:4] == b"\x7fELF":
                self.results["file_type"] = "Linux Shared Object (.so)"
                self.results["executable"] = True
                bit_format = header[4]
                self.results["architecture"] = "32-bit" if bit_format == 1 else "64-bit"
# ;; DLL ;;
          
          elif self.path.suffix.lower() == ".dll":
               if header[:2] == b"MZ":
                  self.results["file_type"] = "Windows Dynamic Link Library (DLL)"
                  self.results["executable"] = False
         
         
# ;; zip ;; 
          elif  header.startswith(b"PK\x03\x04"):
               self.results["file_type"] = "ZIP Archive"
               self.results["executable"] = False

# ;; 7-Zip ;;
          elif header.startswith(b"7z\xBC\xAF\x27\x1C"):
               self.results["file_type"] = "7z Archive"
               self.results["executable"] = False

# ;; RAR ;;
          elif header.startswith(b"Rar!\x1A\x07\x00"):
               self.results["file_type"] = "RAR Archive"
               self.results["executable"] = False

# ;; GZIP ;; 
          elif header.startswith(b"\x1F\x8B\x08"):
               self.results["file_type"] = "GZIP Archive (.gz)"
               self.results["executable"] = False


# ;; BZIP2 ;;
          elif header.startswith(b"BZh"):
               self.results["file_type"] = "BZIP2 Archive (.bz2)"
               self.results["executable"] = False
# ;; TAR ;;
          elif self.path.suffix.lower() == ".tar":
             with open(self.path, "rb") as f:
                  data = f.read(512)
                  if b"ustar" in data:
                     self.results["file_type"] = "TAR Archive"
                     self.results["executable"] = False   





                     
                      

# ;; Text / Encoding Detection ;; 
          if self.results["encoding"].startswith("Unknown"):
             try:
                 with open(self.path,"rb") as f:
                     data = f.read(2048)   
                 if all(32 <= b < 127 or b in (9,10,13) for b in data):
                    self.results["encoding"]  = "ASCII"
                 elif b'\x00' not in data:
                     try:
                         data.decode("utf-8")                      
                         if self.results["file_type"] == "Unknown":
                            self.results["file_type"] = "UTF-8 Text File"
                         self.results["encoding"] = "UTF-8"
                     except UnicodeDecodeError:
                          pass 
             except Exception:
                 pass 

# ;; Executable  ;; 
          if any(word in self.results["file_type"].lower() for word in ["executable", "pe", "elf", "mach-o"]):
             self.results["executable"] = True
          
          return self.results
    

kitty = Kitty_investigator("README.md")
kitty.file_type()
kitty = kitty.detect_binary()
print(kitty)

