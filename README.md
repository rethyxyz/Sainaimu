# Sainaimu
Automated Linux server SSH request blocker for ufw (Uncomplicated Firewall).

## Configuration
The default configuration file is `./Configuration.json`. If this file doesn't exist, it'll be created for you using the template below.
```
{
    "FailCount": 5,
    "AllowedIPAddresses": [ "" ],
    "BlockType": "Deny",
    "Debug": "False"
}
```
If any syntax error occurs in the configuration file, the program will fail to run, and the line/character in question will be highlighted.

### FailCount
```
"FailCount": 5
```
Any numeric value (in the bounds of a signed, standard Python integer) can be placed here.

### AllowedIPAddresses
```
"AllowedIPAddresses": [
    "241.225.138.8",
    "159.124.142.51",
]
```
IP addresses placed as values here are whitelisted from being blocked. Therefore, no addresses here will be blocked from server access no matter the amount of times they fail to logon.

Multiple addresses can be placed here (as seen in the example).

### BlockType
```
"BlockType": "Deny"
```
There are two possible values: `Deny` and `Reject`. You can read about the difference between the two types <a href="https://docs.netgate.com/pfsense/en/latest/firewall/fundamentals.html#:~:text=Deciding%20Between%20Block%20and%20Reject,-There%20has%20been&text=When%20a%20rule%20is%20set,to%20wait%20for%20a%20response.">here</a>.

### Debug
```
"Debug": "False"
```
Two possible values: `"True"`, `"False"`.

`Debug` mode enables a couple of runtime changes:
- Print frequency higher.
- Print function enter/exit.
