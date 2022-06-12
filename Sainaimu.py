'''
Sainaimu. Automated Linux server SSH request blocker for ufw (Uncomplicated
Firewall).
Copyright  (C) 2022  Brody Rethy
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
'''
import os
import sys
import platform
import json

# TODO Ensure that *BSD, and other Unixes use auth.log, or whatever. I think it
# may be an OpenSSH or systemd thing...
# TODO Get list of users on the system from /etc/passwd. Go through this, and
# get awk {print $whatever}.
# TODO PrintDebug() function should take the global variable DEBUG rather than a
# second positional argument.

CONFIGURATION_FILE = "./Configuration.json"
LOG_FILE = "/var/log/auth.log"

FAIL_COUNT_DEFAULT = 5
BLOCK_TYPE_DEFAULT = "Deny"
COLORED_OUTPUT_DEFAULT = "True"
DEBUG_DEFAULT = "False"

def Main():
    Counter = 0
    Stdout = []
    IPAddresses = []
    Dependencies = [ "ufw" ]
    BadOperatingSystems = [ "Java", "Darwin", "Windows" ]
    # These commands are later used to pull information from /var/log/auth.log.
    CheckCommands = [
        ["Invalid user", "10"],
        ["Failed password for root", "11"],
        ["Failed password for invalid user", "13"],
    ]

    CheckPlatforms(BadOperatingSystems)
    CheckArguments()
    CheckRoot()
    CheckDependencies(Dependencies)

    for SystemUser in GetSystemUsers():
        CheckCommands.append([f"Failed password for {SystemUser}", "11"])
    if not FileExists(CONFIGURATION_FILE):
        GenerateConfigurationTemplate(CONFIGURATION_FILE)
    FailCount, AllowedIPAddresses, BlockType = ParseConfigurationFile(CONFIGURATION_FILE)

    if not FileExists(LOG_FILE):
        sys.exit(1)

    for Counter in range(0, len(CheckCommands)):
        # TODO Split this line into smaller bits.
        Stdout = os.popen("grep 'sshd' " + LOG_FILE + " | grep '" + CheckCommands[Counter][0] + "' | awk '{print $" + CheckCommands[Counter][1] + "}' | sort").read().split()
        for Line in Stdout:
            IPAddresses.append(Line)

    if AllowedIPAddresses:
        for IPAddress in AllowedIPAddresses:
            IPAddresses = RemoveStringFromArray(IPAddress, IPAddresses)

    for IPAddress in IPAddresses:
        if IPAddresses.count(IPAddress) >= FailCount:
            BlockIPAddress(IPAddress, BlockType)
            IPAddresses = RemoveStringFromArray(IPAddress, IPAddresses)

    if IPAddresses:
        ReloadFirewall()
    else:
        print(f"{WARNING}No IP addresses blocked.{ENDC}")

    sys.exit(0)

def CheckPlatforms(BadOperatingSystems):
    for OperatingSystem in BadOperatingSystems:
        if platform.system() == OperatingSystem:
            print(f"{FileBasename(sys.argv[0])} can't run on {OperatingSystem}.")
            sys.exit(1)

def CheckDependencies(Dependencies):
    MissingDependencies = []
    for Dependency in Dependencies:
        Output = os.popen(f"which {Dependency}").read().strip()
        if not Output:
            MissingDependencies.append(Dependency)

    if MissingDependencies:
        if len(MissingDependencies) < 2:
            print(f"Missing dependency:")
        else:
            print(f"Missing dependencies:")
        for Dependency in MissingDependencies:
            print(f"\t{Dependency}")
        sys.exit(1)

def GetSystemUsers():
    return os.popen("users")\
        .read()\
        .strip()\
        .split()

def CheckRoot():
    try:
        if os.geteuid():
            print(f"Run {FileBasename(sys.argv[0])} as root.")
            sys.exit(1)
    except AttributeError:
        print(f"{FileBasename(sys.argv[0])} can't run on Windows.")
        sys.exit(1)

def CheckArguments():
    if "--help" in sys.argv or "-h" in sys.argv:
        DisplayHelp()

def DisplayHelp():
    print(f"{FileBasename(sys.argv[0])}: No arguments provided.")
    sys.exit(0)

def BlockIPAddress(IPAddress, BlockType):
    # TODO Implement a SEVERITY option, to see if just blocking SSH access,
    # SSH + Web, or ALL.
    Output = os.popen(f"ufw {BlockType.lower()} from {IPAddress} to any").read().strip()
    if "Skipping" in Output:
        print(f"{WARNING}Already blocked {TITLE}{IPAddress}{ENDC}")
    elif "Rule updated" in Output:
        print(f"{WARNING}Updated rule, now blocking {TITLE}{IPAddress}{ENDC}")
    elif "Rule added" in Output:
        print(f"{GOOD}Blocked {TITLE}{IPAddress}{ENDC}")
    else:
        print(f"{BLUE}Other...{ENDC}")

def RemoveStringFromArray(IPAddress, IPAddresses):
    # TODO This looks bad. Fix this sometime.
    return [value for value in IPAddresses if value != IPAddress]

def ReloadFirewall():
    Output = os.popen("ufw reload").read().strip()
    print(Output)

def GenerateConfigurationTemplate(File):
    with open(File, "w") as FilePointer:
        FilePointer.write("""
{
    \"FailCount\": %s,
    \"ColoredOutput\": \"%s\",
    \"AllowedIPAddresses\": [ \"\" ],
    \"BlockType\": \"%s\",
    \"Debug\": \"%s\"
}
""" % (FAIL_COUNT_DEFAULT, COLORED_OUTPUT_DEFAULT, BLOCK_TYPE_DEFAULT, DEBUG_DEFAULT))
    print(f"Generated configuration file at {File}.")

def FileExists(File):
    Output = os.path.isfile(File)
    if not Output:
        print(f"\"{File}\" doesn't exist.")
    return Output

def PrintDebug(String, DEBUG):
    if DEBUG == "True":
        print(String)

def ParseConfigurationFile(File):
    # Assign the default up here. If anything goes wrong, they'll be skipped
    # later on, and handled in Main().
    global DEBUG
    AllowedIPAddresses = []
    JSONParsed = dict()
    BlockType = BLOCK_TYPE_DEFAULT
    ColoredOutput = COLORED_OUTPUT_DEFAULT
    FailCount = FAIL_COUNT_DEFAULT
    DEBUG = DEBUG_DEFAULT

    try:
        with open(File, "r") as FilePointer:
            JSONContent = FilePointer.read().replace("\n", "")
        JSONParsed = json.loads(JSONContent)
    except json.decoder.JSONDecodeError as ExceptionInformation:
        if DEBUG_DEFAULT == "True":
            PrintDebug(f"Error processing {File}: {ExceptionInformation}.", DEBUG_DEFAULT)
        elif DEBUG_DEFAULT == "False":
            print(f"Error processing {File}.")
        sys.exit(1)

    try:
        DEBUG = JSONParsed["Debug"].capitalize()
        if not DEBUG == "True" and not DEBUG == "False":
            DEBUG = DEBUG_DEFAULT
            PrintDebug(f"{TITLE}\"{DEBUG}\"{BLUE} is an invalid value for DEBUG.{ENDC}", DEBUG)
            PrintDebug(f"{BLUE}Using default value {TITLE}\"{DEBUG_DEFAULT}\"{BLUE}.{ENDC}", DEBUG)
    except KeyError:
        pass

    try:
        ColoredOutput = JSONParsed["ColoredOutput"]
        if ColoredOutput == "True":
            ImplementColors(True)
        else:
            ImplementColors(False)
    except KeyError:
        ImplementColors(False)

    try:
        FailCount = JSONParsed["FailCount"]
    except KeyError:
        pass

    try:
        BlockType = JSONParsed["BlockType"].capitalize()
        if not BlockType == "Reject" and not BlockType == "Deny":
            BlockType = BLOCK_TYPE_DEFAULT
            PrintDebug(f"{TITLE}\"{BlockType}\"{BLUE} is an invalid value for BlockType.{ENDC}", DEBUG)
            PrintDebug("{BLUE}Using default value {TITLE}\"{BLOCK_TYPE_DEFAULT}\"{BLUE}.{ENDC}", DEBUG)
    except KeyError:
        pass

    try:
        AllowedIPAddresses = JSONParsed["AllowedIPAddresses"]
    except KeyError:
        pass

    return FailCount, AllowedIPAddresses, BlockType

def ImplementColors(ColoredOutput):
    global BLUE; global CYAN
    global BOLD; global ENDC; global UNDERLINE; global GOOD; global TITLE; global WARNING; global BAD

    if ColoredOutput:
        BOLD = '\033[1m'
        ENDC = '\033[0m'
        UNDERLINE = '\033[4m'
        GOOD = '\033[92m'
        TITLE = '\033[95m'
        WARNING = '\033[93m'
        BAD = '\033[91m'
        BLUE = '\033[94m'
        CYAN = '\033[96m'
    else:
        BOLD = ""
        ENDC = ""
        UNDERLINE = ""
        GOOD = ""
        TITLE = ""
        WARNING = ""
        BAD = ""
        BLUE = ""
        CYAN = ""

def FileBasename(File):
    return os.path.basename(File)

Main()