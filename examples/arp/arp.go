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

	log.Printf("Attempting to arp %s", dstip4)

	// ARP
	dstaddr, err := nm.ARP(dstip4)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("IP %s is at %s", dstip4, dstaddr)
}
