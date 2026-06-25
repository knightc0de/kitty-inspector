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

class Kitty_investigator():
      def __init__(self,path):
            self.path = Path(path)
            self.results = results.copy()
    
      def file_type(self):
        try:
            ext = self.path.suffix.lower()

            if ext == ".py":
                self.results["file_type"] = "Python Script"

            elif ext == ".c":
                self.results["file_type"] = "C Source File"

            elif ext in [".cpp", ".cc", ".cxx"]:
                self.results["file_type"] = "C++ Source File"

            elif ext in [".sh", ".bash", ".zsh"]:
                self.results["file_type"] = "Shell Script"

            elif ext in [".html", ".htm"]:
                self.results["file_type"] = "HTML Document"

            elif ext == ".php":
                self.results["file_type"] = "PHP Script"

            elif ext == ".js":
                self.results["file_type"] = "JavaScript File"

            elif ext == ".java":
                self.results["file_type"] = "Java Source File"

            else:
                self.results["file_type"] = f"Unknown ({ext})"

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
          return self.results 





kitty = Kitty_investigator("64bit.7z")
kitty.file_type()
kitty = kitty.detect_binary()
print(kitty)

