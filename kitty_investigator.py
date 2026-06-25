from argparse import FileType
import struct 
from  pathlib import Path 
import sys 
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

# : windows PE :
      
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
          else: 
                 self.results["file_type"] = "Unknown"

          return self.results
      





kitty = Kitty_investigator("08_prob.exe")
kitty.file_type()
kitty = kitty.detect_binary()
print(kitty)

