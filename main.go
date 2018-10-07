package main

import (
	"fmt"
	"gopacketDemo/sniff"
)

func main() {
	sniffer := &sniff.Sniffer{Domain: "www.google.com", Port: 80}
	sniffer.Start()

	for packet := range sniffer.ApplicationPayloads() {
		fmt.Println(string(packet))
	}
}

