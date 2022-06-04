# Sainaimu
Automated Linux server SSH request blocker for ufw (Uncomplicated Firewall).

## Configuration
The default configuration file is `./Configuration.json`. If this file doesn't exist, it'll be created for you using the template below.
```
{
    "FailCount": 5,
    "ColoredOutput": "True",
    "AllowedIPAddresses": [ "" ]
}
```

If any syntax error occurs in the configuration file, the program will fail to run, and the line/character in question will be highlighted.

### FailCount
```
"FailCount": 5
```
Any numeric value (in the bounds of a signed, standard Python integer) can be placed here.

### ColoredOutput
```
"ColoredOutput": "True",
```
Can be toggled between `True` and `False`.

### AllowedIPAddresses
```
"AllowedIPAddresses": [
    "241.225.138.8",
    "159.124.142.51",
]
```
IP addresses placed as values here are whitelisted from being blocked. Therefore, no addresses here will be blocked from server access no matter the amount of times they fail to logon.

Multiple addresses can be placed here (as seen in the example).