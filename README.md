# `networkmonster`, networking made difficult

Everything here is for recreational purposes only

## Usage
Just include `networkmonster` as a dependency in your project:
```
import (
    "github.com/mgmcintyre/networkmonster"
)
```

## Running the examples
You'll need privileged access to create raw sockets:
```
$ sudo GOPATH=/path/to/go go run examples/ping/ping.go 192.168.0.100
OR
$ go build examples/ping/ping.go && sudo ./ping 10.32.0.134
```

## Note on Layer 2 OS translation
This code will run whether you're connected via ethernet or Wi-Fi.
Your host OS (or the network driver, I'm not really sure which) translates your
Ethernet frames to 802.11 before they are sent over your Wi-Fi connection.

## What next
+ Emulate standard `ping` behaviour
+ Default gateway for interface
+ Routing tables (for ARP)
+ External ping
+ Tests (e.g. byte-level checks)
