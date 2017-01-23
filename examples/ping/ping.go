package main

import (
	"log"
	"net"

	"github.com/mgmcintyre/go-playground/networkmonster"
)

func main() {
	nm, err := networkmonster.NewNetworkMonster("en0")
	if err != nil {
		log.Fatal(err)
	}
	defer nm.Close()

	dstip := net.IP{10, 10, 51, 89}
	// dstip := net.IP{8, 8, 4, 4}
	log.Printf("Attempting to ping %s", dstip)

	// ICMP
	if _, err := nm.PingOnce(dstip); err != nil {
		log.Fatal(err)
	}

}
