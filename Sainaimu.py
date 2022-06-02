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

# TODO Ensure that *BSD, and other Unixes use auth.log, or whatever. I think
# it may be an OpenSSH or systemd thing...
# TODO Get list of users on the system from /etc/passwd. Go through this, and
# get awk {print $whatever}.

CONFIGURATION_FILE = "./Configuration.json"
LOG_FILE = "/var/log/auth.log"

def Main():
    Counter = 0
    Stdout = []
    IPAddresses = []
    Dependencies = [ "ufw" ]
    # These commands are later used to pull information from /var/log/auth.log.
    CheckCommands = [
        ["Invalid user", "10"],
        ["Failed password for root", "11"],
        ["Failed password for invalid user", "13"],
    ]
    for SystemUser in GetSystemUsers():
        CheckCommands.append([f"Failed password for {SystemUser}", "11"])
    if not FileExists(CONFIGURATION_FILE):
        GenerateConfigurationTemplate(CONFIGURATION_FILE)
    FailCount, AllowedIPAddresses = ParseConfigurationFile(CONFIGURATION_FILE)

    CheckRoot()
    CheckDependencies(Dependencies)

    if not FileExists(LOG_FILE): sys.exit(1)

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
            BlockIPAddress(IPAddress)
            IPAddresses = RemoveStringFromArray(IPAddress, IPAddresses)

    if IPAddresses:
        ReloadFirewall()
    else:
        print(f"{WARNING}No IP addresses blocked.{ENDC}")

    sys.exit(0)

def CheckDependencies(Dependencies):
    MissingDependencies = []
    for Dependency in Dependencies:
        Output = os.popen(f"which {Dependency}").read().strip()
        if not Output:
            MissingDependencies.append(Dependency)

    if MissingDependencies:
        if len(MissingDependencies) < 2:
            print(f"{BAD}Missing dependency:{ENDC}")
        else:
            print(f"{BAD}Missing dependencies:{ENDC}")
        for Dependency in MissingDependencies:
            print(f"\t{TITLE}{Dependency}{ENDC}")
        sys.exit(1)

def GetSystemUsers():
    return os.popen("users").read().strip().split()

def CheckRoot():
    if os.geteuid():
        print(f"Run {sys.argv[0]} as root.")
        sys.exit(1)

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

def BlockIPAddress(IPAddress):
    # TODO Implement a SEVERITY option, to see if just blocking SSH access,
    # SSH + Web, or ALL.
    Output = os.popen(f"ufw deny from {IPAddress} to any").read().strip()

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
    print(f"Generating configuration file at {File}.")
    with open(File, "w") as FilePointer:
        FilePointer.write("""
        {
            \"FailCount\": 5,
            \"ColoredOutput\": \"True\",
            \"AllowedIPAddresses\": [ \"\" ]
        }
        """)

def FileExists(File):
    Output = os.path.isfile(File)
    if not Output:
        print(f"{TITLE}{File}{BLUE} file doesn't exist.{ENDC}")
    return Output

def ParseConfigurationFile(File):
    # Assign the default up here. If anything goes wrong, they'll be skipped
    # later on, and handled in Main().
    AllowedIPAddresses = []
    JSONParsed = dict()
    FailCount = 5

    try:
        with open(File, "r") as FilePointer:
            JSONContent = FilePointer.read().replace("\n", "")
        JSONParsed = json.loads(JSONContent)
    except json.decoder.JSONDecodeError as ExceptionInformation:
        print(f"{BAD}Error processing {TITLE}{File}{BAD}: {BLUE}{ExceptionInformation}{ENDC}")

    try:
        FailCount = JSONParsed["FailCount"]
    except KeyError:
        pass

    try:
        AllowedIPAddresses = JSONParsed["AllowedIPAddresses"]
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

    return FailCount, AllowedIPAddresses

if platform.system == "Windows":
    print(sys.argv[0] + " cannot run on Windows.")
else:
    Main()
