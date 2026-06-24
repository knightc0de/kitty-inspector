import struct 
from  pathlib import Path 
import magic 
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
               m = magic.Magic(mime=True)
               ftype = m.from_file(str(self.path))
               ftype = ftype.split(",")[0].strip()
               self.results["file_type"] = ftype
               ext = Path(self.path).suffix.lower()
               if ext == ".py":
                      self.results["file_type"] = "Python Script"
               elif ext == ".c":
                      self.results["file_type"] = "C Source File"
               elif ext in [".cpp", ".cc", ".cxx"]:
                      self.results["file_type"] = "C++ Source File"
               elif ext in [".sh",".bash",".zsh"]:
                      self.results["file_type"] = "Shell Script"
               elif ext == ".html" or ext == ".htm":
                      self.results["file_type"] = "HTML Document"
               elif ext == ".php":
                      self.results["file_type"] = "PHP Script"
               elif ext == ".js":
                     self.results["file_type"] = "JavaScript File"
               elif ext == ".java":
                     self.results["file_type"] = "Java Source File"
             
          except Exception:
              self.results["file type"] = "Unknown (magic unavailable)"

