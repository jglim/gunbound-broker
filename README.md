# GunBound Broker Server (Thor's Hammer)

Emulates the GunBound **classic** broker server, which powers the World selection screen.

![World Select Screenshot](https://raw.github.com/jglim/gunbound-broker/master/other/banner.png)

---

# Why
A set official-looking GunBound server files were leaked many years ago. Conspicuously missing was a broker server, and homebrew alternatives were proprietary and lacking in features.

# Features
- Flexible server list, described in a `directory.json` file
- Every individual server entry can direct to a unique address and port
- Additional options for setting the server's utilization visual indicator
- Servers entries can be disabled ("maintenance mode")
- Open source!

# Usage
Run either `broker.exe` for Windows, or `broker.py` for other platforms (Requires Python 3.x). 
Take a look at `directory.json` to see examples of server configurations.

# Documentation

- By default, the GunBound broker runs on port `8372` (TCP).
- The client can connect to a different IP/Port by changing the values of `IP` and `port` at `HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\SoftNyx\GunBound`. Omit `Wow6432Node` for 32-bit systems.
- The client's authentication data is ignored as the actual check is made when connecting to a specific world
- The avatar bonus effects are enabled/disabled on the game server, not the broker.

### GunBound Packet Layout

An example packet (Server -> Client)

|Position     |00|01|02|03|04|05|06|07|08|09|0a|0b|
|-------------|--|--|--|--|--|--|--|--|--|--|--|--|
|Packet Data  |0c|00|eb|cb|12|13|30|00|ff|ff|ff|ff|
```
00, 01 = Packet size, 00 = LSB, 01 = MSB
02, 03 = Packet sequence
04, 05 = Command
06 ... = Parameters/Data
```

### Packet Sequence

The GunBound packet sequence value is generated from the total sent packets per connection
Normally the overall length is stored/incremented per socket, but the broker only uses this once
The _magic values_ are taken from function at `0x40B760` in `GunBoundServ2.exe` (SHA-1: `b8fce1f100ef788d8469ca0797022b62f870b79b`)
```
ECX: packet length
0040B799  IMUL CX,CX,43FD ; Multiply packet length with 43FD (int16)
0040B79E  ...
0040B7A1  ...
0040B7A9  ...
0040B7AB  ...
0040B7B2  ADD ECX,FFFFAC03 ; Inverted sign of FFFFAC03 equivalent would be SUB 53FD (implemented below)
```
The client verifies the packet's integrity and order using the generated value. 
For the server to verify the client's packet sequence, subtract `0x613D` instead

## Broker Commands
#### Client to Server
- Login Request Command: `0x1310` 
- Server List Request Command: `0x1100`

#### Server to Client
- Server List Response Command: `0x1102`
- Login Response Command: `0x1312`
```
response_success = 0x0000
response_bad_username = 0x0010
response_bad_password = 0x0011
response_banned_user = 0x0030
response_bad_version = 0x0060
```
---
# License

MIT

