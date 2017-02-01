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

## What next
+ LLDP
+ Emulate standard `ping` behaviour
+ Default gateway for interface
+ Routing tables (for ARP)
+ External ping
+ Tests (e.g. byte-level checks)
