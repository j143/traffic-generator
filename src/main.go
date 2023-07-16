package main

import (
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	// Get a list of available network interfaces
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	// Print available interfaces
	for _, iface := range ifaces {
		fmt.Println("Name:", iface.Name)
		fmt.Println("Description:", iface.Description)
		fmt.Println()
	}

	// Choose the desired interface
	selectedInterface := `\Device\NPF_{E2D1DD3A-B013-43BE-B95A-D9F3C0845925}` // Replace with the desired interface name

	// Open the network interface for packet injection
	iface, err := pcap.OpenLive(selectedInterface, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer iface.Close()

	// Craft and send packets
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{}

	ethLayer := &layers.Ethernet{
		DstMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		SrcMAC:       net.HardwareAddr{0x55, 0x44, 0x33, 0x22, 0x11, 0x00},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipLayer := &layers.IPv4{
		SrcIP:    net.IP{192, 168, 1, 1},
		DstIP:    net.IP{192, 168, 1, 2},
		Protocol: layers.IPProtocolTCP,
	}

	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(1234),
		DstPort: layers.TCPPort(80),
	}

	err = gopacket.SerializeLayers(buffer, options, ethLayer, ipLayer, tcpLayer)
	if err != nil {
		log.Fatal(err)
	}

	err = iface.WritePacketData(buffer.Bytes())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Packet sent!")
}
