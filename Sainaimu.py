#!/usr/bin/env python3

# TODO: Ensure that *BSD, and other Unixes use auth.log, or whatever. I think it
# may be an OpenSSH or systemd thing...

import os
import sys
import json
import stdlib

from color import *

LOG_FILE                  = "/var/log/auth.log"
CONFIGURATION_FILE        = os.path.expanduser("~") + "/Configuration.json"

MAX_LOGIN_ATTEMPT_DEFAULT = 5
BLOCK_TYPE_DEFAULT        = "Deny"
COLORED_OUTPUT_DEFAULT    = "True"

FIREWALL                  = "ufw"
RELOAD_STRING             = "reload"

def Main():
    counter             = 0
    stdout              = []
    IPAddresses         = []
    dependencies        = [ "ufw" ]
    badOperatingSystems = [ "Java", "Darwin", "Windows" ]
    # These commands are later used to pull information from /var/log/auth.log.
    CheckCommands = [
        ["Invalid user", "10"],
        ["Failed password for root", "11"],
        ["Failed password for invalid user", "13"],
    ]

    stdlib.CheckPlatforms(badOperatingSystems)
    CheckArguments()
    stdlib.CheckUID()
    CheckDependencies(dependencies)

    for systemUser in stdlib.GetSystemUser():
        CheckCommands.append([f"Failed password for {systemUser}", "11"])
        
    if not stdlib.File.Exists(CONFIGURATION_FILE):
        GenerateConfigurationTemplate(CONFIGURATION_FILE)

    maxLoginAttempt, allowedIPAddresses, firewallBlockType = ParseConfigurationFile(CONFIGURATION_FILE)

    if not stdlib.File.Exists(LOG_FILE):
        sys.exit(1)

    for counter in range(0, len(CheckCommands)):
        # TODO Split this line into smaller bits.
        stdout = os.popen("grep 'sshd' " + LOG_FILE + " | grep '" + CheckCommands[counter][0] + "' | awk '{print $" + CheckCommands[counter][1] + "}' | sort").read().split()
        for line in stdout:
            IPAddresses.append(line)

    if allowedIPAddresses:
        for IPAddress in allowedIPAddresses:
            IPAddresses = RemoveStringFromArray(IPAddress, IPAddresses)

    for IPAddress in IPAddresses:
        if IPAddresses.count(IPAddress) >= maxLoginAttempt:
            BlockIPAddress(IPAddress, firewallBlockType)
            IPAddresses = RemoveStringFromArray(IPAddress, IPAddresses)

    if IPAddresses:
        RefreshFirewallConfiguration()
    else:
        print(f"{WARNING}No IP addresses blocked.{ENDC}")

    sys.exit(0)

def CheckDependencies(dependencies):
    missingDependencies = []
    for dependency in dependencies:
        output = os.popen(f"which {dependency}").read().strip()
        if not output:
            missingDependencies.append(dependency)

    if missingDependencies:
        if len(missingDependencies) < 2:
            print(f"{BAD}Missing dependency:{ENDC}")
        else:
            print(f"{BAD}Missing dependencies:{ENDC}")
        
        for dependency in missingDependencies:
            print(f"\t{TITLE}{dependency}{ENDC}")
            
        sys.exit(1)

def CheckArguments():
    if "--help" in sys.argv or "-h" in sys.argv:
        Help()

def Help():
    print(f"{TITLE}{stdlib.File.GetBasename(sys.argv[0])}{ENDC}: {WARNING}No arguments provided.{ENDC}")
    sys.exit(0)

def BlockIPAddress(IPAddress, firewallBlockType):
    # TODO Implement a SEVERITY option, to see if just blocking SSH access,
    # SSH + Web, or ALL.
    output = os.popen(f"ufw {firewallBlockType.lower()} from {IPAddress} to any").read().strip()
    if "Skipping" in output:
        print(f"{WARNING}Already blocked {TITLE}{IPAddress}{WARNING}.{ENDC}")
    elif "Rule updated" in output:
        print(f"{WARNING}Updated rule, now blocking {TITLE}{IPAddress}{WARNING}.{ENDC}")
    elif "Rule added" in output:
        print(f"{GOOD}Blocked {TITLE}{IPAddress}{GOOD}.{ENDC}")
    else:
        print(f"{BLUE}Other...{ENDC}")

def RemoveStringFromArray(IPAddress, IPAddresses):
    # TODO: This looks bad. Fix this sometime.
    return [value for value in IPAddresses if value != IPAddress]

def RefreshFirewallConfiguration():
    output = os.popen(f"{FIREWALL} {RELOAD_STRING}").read().strip()
    print(output)

def GenerateConfigurationTemplate(f):
    with open(f, "w") as f_ptr:
        f_ptr.write("""
{
    \"FailCount\": %s,
    \"AllowedIPAddresses\": [ \"\" ],
    \"BlockType\": \"%s\"
}
""" % (MAX_LOGIN_ATTEMPT_DEFAULT, BLOCK_TYPE_DEFAULT))
    print(f"{WARNING}Generated configuration file at {TITLE}{f}{ENDC}.")

def ParseConfigurationFile(file):
    # Assign the default up here. If anything goes wrong, they'll be skipped
    # later on, and handled in main().
    allowedIPAddresses = []
    jsonParsed         = dict()
    firewallBlockType  = BLOCK_TYPE_DEFAULT
    maxLoginAttempt    = MAX_LOGIN_ATTEMPT_DEFAULT

    try:
        with open(file, "r") as f_ptr:
            jsonContent = f_ptr.read().replace("\n", "")
        jsonParsed = json.loads(jsonContent)
    except json.decoder.JSONDecodeError as ExceptionInformation:
        print(f"Error processing {file}: {ExceptionInformation}.")
        sys.exit(1)

    try:
        maxLoginAttempt = jsonParsed["FailCount"]
    except KeyError:
        pass

    try:
        firewallBlockType = jsonParsed["BlockType"].capitalize()
    
        if not firewallBlockType == "Reject" and not firewallBlockType == "Deny":
            firewallBlockType = BLOCK_TYPE_DEFAULT
            print(f"{TITLE}\"{firewallBlockType}\"{BLUE} is an invalid value for block_type.{ENDC}")
            print("{BLUE}Using default value {TITLE}\"{BLOCK_TYPE_DEFAULT}\"{BLUE}.{ENDC}")
    except KeyError:
        pass

    try:
        allowedIPAddresses = jsonParsed["AllowedIPAddresses"]
    except KeyError:
        pass

    return maxLoginAttempt, allowedIPAddresses, firewallBlockType

if __name__ == '__main__':
    Main()