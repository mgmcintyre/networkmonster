package networkmonster

import (
	"bytes"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// NetworkMonster provides basic networking functionality using raw sockets
type NetworkMonster struct {
	handle        *pcap.Handle
	iface         *net.Interface
	srcip         net.IP
	packetReaders packetReaderList
}

type packetReaderList struct {
	sync.Mutex
	members []chan gopacket.Packet
}

func getSourceIP(iface *net.Interface) net.IP {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			if srcip := ipnet.IP.To4(); srcip != nil {
				log.Printf("Found IP address %s for interface %s", srcip, iface.Name)
				return srcip
			}
		}
	}

	return nil
}

func (nm *NetworkMonster) writeARP(dstip net.IP) error {
	// Set up all the layers' fields we can.
	eth := layers.Ethernet{
		SrcMAC:       nm.iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(nm.iface.HardwareAddr),
		SourceProtAddress: []byte(nm.srcip),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(dstip),
	}

	// Set up buffer and options for serialization.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		return err
	}

	if err := nm.handle.WritePacketData(buf.Bytes()); err != nil {
		return err
	}

	return nil
}

func (nm *NetworkMonster) readARP(dstip net.IP) chan net.HardwareAddr {
	out := make(chan net.HardwareAddr, 1)

	go func() {
		packets, done := nm.readPackets()
		for packet := range packets {
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)

			if arp.Operation == layers.ARPReply && bytes.Equal([]byte(dstip), arp.SourceProtAddress) {
				done <- struct{}{}
				out <- net.HardwareAddr(arp.SourceHwAddress)
				break
			}
		}
	}()

	return out
}

// ARP sends an ARP request for the given IP address
func (nm *NetworkMonster) ARP(dstip net.IP) (net.HardwareAddr, error) {
	log.Print("Listening for ARP reply")
	arpreply := nm.readARP(dstip)

	log.Printf("Making ARP request for %s", dstip)
	if err := nm.writeARP(dstip); err != nil {
		return nil, err
	}

	var dstaddr net.HardwareAddr
	select {
	case <-time.After(5000 * time.Millisecond):
		return nil, errors.New("No ARP reply received")
	case dstaddr = <-arpreply:
		log.Printf("Received ARP reply, %s is at %s", dstip, dstaddr)
		return dstaddr, nil
	}
}

func (nm *NetworkMonster) writePing(dstip net.IP, dstaddr net.HardwareAddr) (start time.Time, err error) {
	// Ethernet layer
	eth := layers.Ethernet{
		SrcMAC:       nm.iface.HardwareAddr,
		DstMAC:       dstaddr,
		EthernetType: layers.EthernetTypeIPv4,
	}

	// IPv4 layer
	ipv4 := layers.IPv4{
		SrcIP:    nm.srcip,
		DstIP:    dstip,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolICMPv4,
	}

	// ICMP layer
	icmp := layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Id:       0x1337,
	}

	// Payload
	payload := gopacket.Payload([]byte("woofwoofwoof"))

	// Create packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err = gopacket.SerializeLayers(buf, opts, &eth, &ipv4, &icmp, &payload); err != nil {
		return
	}

	// Write to device
	if err = nm.handle.WritePacketData(buf.Bytes()); err != nil {
		return
	}

	return time.Now(), nil
}

func (nm *NetworkMonster) readPing(dstip net.IP) chan struct{} {
	out := make(chan struct{}, 1)

	go func() {
		packets, done := nm.readPackets()
		for packet := range packets {
			icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
			if icmpLayer == nil {
				continue
			}
			icmp := icmpLayer.(*layers.ICMPv4)

			if icmp.TypeCode == layers.ICMPv4TypeEchoReply {
				done <- struct{}{}
				out <- struct{}{}
				break
			}
		}
	}()

	return out
}

// PingOnce sends a single ICMP ping request to the given IP
func (nm *NetworkMonster) PingOnce(dstip net.IP) (*time.Duration, error) {

	dstaddr, err := nm.ARP(dstip)
	if err != nil {
		return nil, err
	}

	log.Print("Listening for ping reply")
	pingreply := nm.readPing(dstip)

	log.Printf("Making ping request to %s", dstip)
	start, err := nm.writePing(dstip, dstaddr)
	if err != nil {
		log.Fatal(err)
	}

	select {
	case <-time.After(5000 * time.Millisecond):
		return nil, errors.New("No ping reply received")
	case <-pingreply:
		duration := time.Since(start)
		log.Printf("Received ping reply, after %s", duration)
		return &duration, nil
	}
}

func getInterface(name string) (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		if iface.Name == name {
			return &iface, nil
		}
	}

	return nil, errors.New("interface not found")
}

// Close tidies up the open socket
func (nm *NetworkMonster) Close() {
	nm.handle.Close()
}

func (nm *NetworkMonster) readPackets() (chan gopacket.Packet, chan struct{}) {
	out := make(chan gopacket.Packet)
	done := make(chan struct{}, 1)

	// Lock to add the outbound channel & set up done channel handler
	nm.packetReaders.Lock()

	// Add out channel to packet readers list & note the index
	nm.packetReaders.members = append(nm.packetReaders.members, out)
	i := len(nm.packetReaders.members) - 1

	// Wait for the done channel in the background to remove the out channel
	go func() {
		<-done
		nm.packetReaders.Lock()
		l := len(nm.packetReaders.members)
		nm.packetReaders.members[l-1] = nm.packetReaders.members[i]
		nm.packetReaders.members[i] = nm.packetReaders.members[l-1]
		nm.packetReaders.members = nm.packetReaders.members[:l-1]
		nm.packetReaders.Unlock()
	}()

	nm.packetReaders.Unlock()

	// If we added the first packet reader then we're starting or restarting
	if i == 0 {
		go func() {
			src := gopacket.NewPacketSource(nm.handle, layers.LinkTypeEthernet)
			for {
				packet, err := src.NextPacket()
				if err == io.EOF {
					break
				} else if err != nil {
					log.Println("Error:", err)
					continue
				}
				nm.packetReaders.Lock()
				if len(nm.packetReaders.members) > 0 {
					for _, reader := range nm.packetReaders.members {
						reader <- packet
					}
				} else {
					break
				}
				nm.packetReaders.Unlock()
			}
		}()
	}

	return out, done
}

// NewNetworkMonster builds a NetworkMonster for the given interface
func NewNetworkMonster(interfaceName string) (*NetworkMonster, error) {
	log.Print("Searching for interface")
	iface, err := getInterface(interfaceName)
	if err != nil {
		return nil, err
	}
	srcip := getSourceIP(iface)

	log.Printf("Opening raw socket on %s", iface.Name)
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	nm := &NetworkMonster{
		handle: handle,
		iface:  iface,
		srcip:  srcip,
	}

	return nm, nil
}
