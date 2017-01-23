package main

import (
	"log"
	"net"
	"os"

	"github.com/mgmcintyre/networkmonster"
)

func main() {
	nm, err := networkmonster.NewNetworkMonster("en0")
	if err != nil {
		log.Fatal(err)
	}
	defer nm.Close()

	dstip := net.ParseIP(os.Args[1])
	if dstip == nil {
		log.Fatal("Invalid IP address provided")
	}

	dstip4 := dstip.To4()
	if dstip4 == nil {
		log.Fatal("Only IPv4 addresses accepted")
	}

	log.Printf("Attempting to ping %s", dstip4)

	// ICMP
	if _, err := nm.PingOnce(dstip4); err != nil {
		log.Fatal(err)
	}

}
