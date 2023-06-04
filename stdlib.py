import os
import sys
import platform
from color import *

class Directory:
    def Exists(directory):
        if not os.path.isdir(directory):
            return False
        return True

class File:
    def GetBasename(file):
        return os.path.basename(file)
    
    def Exists(file):
        if not os.path.isfile(file):
            return False
        return True

def GetSystemUser():
    return os.popen("users")\
        .read()\
        .strip()\
        .split()

def CheckUID():
    try:
        if os.geteuid():
            print(f"{BAD}Run {TITLE}{File.GetBasename(sys.argv[0])}{BAD} as root.{ENDC}")
            sys.exit(1)
    except AttributeError:
        # Don't use color vars here. Windows can't interpret them.
        print(f"{File.GetBasename(sys.argv[0])} can't run on Windows.")
        sys.exit(1)

def CheckPlatforms(badOS):
    for os in badOS:
        if platform.system() == os:
            print(f"{File.GetBasename(sys.argv[0])} can't run on {os}.")
            sys.exit(1)
