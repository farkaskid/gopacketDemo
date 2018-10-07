package sniff

import (
	"net"
	"log"

	pac    "github.com/google/gopacket"
	layers "github.com/google/gopacket/layers"
)

type Sniffer struct {
	Domain   string
	Port     int
	packets  chan []byte
	signal   chan bool
}

func (sniffer *Sniffer) Stop() {
	sniffer.signal <- true
}

func (sniffer *Sniffer) listen() {
	conn, err := net.ListenIP("ip4:tcp", new(net.IPAddr))
	if err != nil {
			log.Panicln(err)
	}
	buf := make([]byte, 2048)
	for {
		select {
			case <-sniffer.signal:
				break
			default:
				_, ip, err := conn.ReadFrom(buf)
				if err != nil {
						break
				}
				domains, err := net.LookupAddr(ip.String())
				if err != nil {
					continue
				}

				log.Println(domains)

				packet := pac.NewPacket(buf, layers.LayerTypeTCP, pac.Default)
				if len(sniffer.packets) != cap(sniffer.packets) {
					sniffer.packets <- packet.ApplicationLayer().Payload()
				}
		}
	}
}

//func checkDomains(domains []string, givenDomain string) bool {
//	present := false

//	for domain := range domains {
//		if 

func (sniffer *Sniffer) Start() {
	sniffer.packets = make(chan []byte, 10)
	sniffer.signal = make(chan bool)
	go sniffer.listen()
}

func (sniffer *Sniffer) ApplicationPayloads() <-chan []byte {
	return sniffer.packets
}
