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


kitty = Kitty_investigator("req.py")
kitty = kitty.file_type()
print(kitty)
