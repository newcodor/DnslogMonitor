package main

import (
	"bytes"
	"encoding/binary"
	// "fmt"
	"io"
	"log"
	"net"
	// "net/http"
	"strings"
	// "error"
)

var (
	serverAddr string = "0.0.0.0"
	port       int    = 53
	ResolveIP  net.IP = net.ParseIP("127.0.0.1")
	DNSrecords []string
	DNSType    map[uint16]string = map[uint16]string{
		1:  "A",
		2:  "NS",
		5:  "CNAME",
		6:  "SOA",
		12: "PTR",
		15: "MX",
		16: "TXT",
		28: "AAAA",
		33: "SRV",
	}
)

const (
	UDPMaxMessageSizeBytes int    = 512
	TypeA                  uint16 = 1 // a host address
	ClassINET              uint16 = 1 // the Internet
	FlagResponse           uint16 = 1 << 15
)

type DNSHeader struct {
	Id                                 uint16
	Bits                               uint16
	Qdcount, Ancount, Nscount, Arcount uint16
}

type DNSResourceRecord struct {
	DomainName         string
	Type               uint16
	Class              uint16
	TimeToLive         uint32
	ResourceDataLength uint16
	ResourceData       []byte
}

func Write(w io.Writer, data interface{}) error {
	return binary.Write(w, binary.BigEndian, data)
}

func readDomainName(requestBuffer *bytes.Buffer) (string, error) {
	var domainName string

	b, err := requestBuffer.ReadByte()

	for ; b != 0 && err == nil; b, err = requestBuffer.ReadByte() {
		labelLength := int(b)
		labelBytes := requestBuffer.Next(labelLength)
		labelName := string(labelBytes)

		if len(domainName) == 0 {
			domainName = labelName
		} else {
			domainName += "." + labelName
		}
	}

	return domainName, err
}

func writeDomainName(responseBuffer *bytes.Buffer, domainName string) error {
	labels := strings.Split(domainName, ".")

	for _, label := range labels {
		labelLength := len(label)
		labelBytes := []byte(label)

		responseBuffer.WriteByte(byte(labelLength))
		responseBuffer.Write(labelBytes)
	}

	err := responseBuffer.WriteByte(byte(0))

	return err
}

func dbLookup(queryResourceRecord DNSResourceRecord) ([]DNSResourceRecord, []DNSResourceRecord, []DNSResourceRecord) {
	var answerResourceRecords = make([]DNSResourceRecord, 0)
	var authorityResourceRecords = make([]DNSResourceRecord, 0)
	var additionalResourceRecords = make([]DNSResourceRecord, 0)

	if queryResourceRecord.Type != TypeA {
		return answerResourceRecords, authorityResourceRecords, additionalResourceRecords
	}
	answerResourceRecords = append(answerResourceRecords, DNSResourceRecord{
		DomainName:         queryResourceRecord.DomainName,
		Type:               TypeA,
		Class:              ClassINET,
		TimeToLive:         31337,
		ResourceData:       ResolveIP[12:16], // ipv4 address
		ResourceDataLength: 4,
		// ResourceDataLength: uint16(len(ResolveIP)),
	})

	return answerResourceRecords, authorityResourceRecords, additionalResourceRecords
}

func handleDNSRequest(udpConn *net.UDPConn, addr *net.UDPAddr, data []byte) {
	buf := bytes.NewBuffer(data)
	var reqHeader DNSHeader
	var err error
	binary.Read(buf, binary.BigEndian, &reqHeader)
	reqResourceRecords := make([]DNSResourceRecord, reqHeader.Qdcount)
	for i, _ := range reqResourceRecords {
		if reqResourceRecords[i].DomainName, err = readDomainName(buf); err != nil {
			log.Println("recevie error format data")
			return
		}
		reqResourceRecords[i].Type = binary.BigEndian.Uint16(buf.Next(2))
		reqResourceRecords[i].Class = binary.BigEndian.Uint16(buf.Next(2))
		log.Printf("Client ID:%d,Client Addr: %s,Msg Count:%d,Domain: %s,Type: %v,Class: %d", reqHeader.Id, addr, len(data), reqResourceRecords[i].DomainName, DNSType[reqResourceRecords[i].Type], reqResourceRecords[i].Class)
	}
	if reqResourceRecords == nil || len(reqResourceRecords) == 0 {
		// log.Fatal("recevie error data,exit current thread")
		// log.Panic("recevie error data,exit current thread")
		log.Println("recevie error data,exit current thread")
		return
	}
	var answerResourceRecords = make([]DNSResourceRecord, 0)
	var authorityResourceRecords = make([]DNSResourceRecord, 0)
	var additionalResourceRecords = make([]DNSResourceRecord, 0)

	for _, queryResourceRecord := range reqResourceRecords {
		newAnswerRR, newAuthorityRR, newAdditionalRR := dbLookup(queryResourceRecord)

		answerResourceRecords = append(answerResourceRecords, newAnswerRR...) // three dots cause the two lists to be concatenated
		authorityResourceRecords = append(authorityResourceRecords, newAuthorityRR...)
		additionalResourceRecords = append(additionalResourceRecords, newAdditionalRR...)
	}
	// log.Println(reqResourceRecords[0].DomainName)
	DNSrecords = append(DNSrecords, strings.Join([]string{addr.String(), reqResourceRecords[0].DomainName}, ""))
	var responseBuffer = new(bytes.Buffer)
	responseHeader := DNSHeader{
		Id:      reqHeader.Id,
		Bits:    FlagResponse,
		Qdcount: reqHeader.Qdcount,
		Ancount: uint16(len(answerResourceRecords)),
		Nscount: uint16(len(authorityResourceRecords)),
		Arcount: uint16(len(additionalResourceRecords)),
	}
	err = Write(responseBuffer, &responseHeader)
	if err != nil {
		log.Fatal("Error writing to buffer: %v", err.Error())
	}

	for _, queryResourceRecord := range reqResourceRecords {
		err = writeDomainName(responseBuffer, queryResourceRecord.DomainName)

		if err != nil {
			log.Fatal("Error writing to buffer: %v", err.Error())
		}

		Write(responseBuffer, queryResourceRecord.Type)
		Write(responseBuffer, queryResourceRecord.Class)
	}

	for _, answerResourceRecord := range answerResourceRecords {
		err = writeDomainName(responseBuffer, answerResourceRecord.DomainName)

		if err != nil {
			log.Fatal("Error writing to buffer: %v", err.Error())
		}

		Write(responseBuffer, answerResourceRecord.Type)
		Write(responseBuffer, answerResourceRecord.Class)
		Write(responseBuffer, answerResourceRecord.TimeToLive)
		Write(responseBuffer, answerResourceRecord.ResourceDataLength)
		Write(responseBuffer, answerResourceRecord.ResourceData)
	}

	for _, authorityResourceRecord := range authorityResourceRecords {
		err = writeDomainName(responseBuffer, authorityResourceRecord.DomainName)

		if err != nil {
			log.Fatal("Error writing to buffer: %v", err.Error())
		}

		Write(responseBuffer, authorityResourceRecord.Type)
		Write(responseBuffer, authorityResourceRecord.Class)
		Write(responseBuffer, authorityResourceRecord.TimeToLive)
		Write(responseBuffer, authorityResourceRecord.ResourceDataLength)
		Write(responseBuffer, authorityResourceRecord.ResourceData)
	}

	for _, additionalResourceRecord := range additionalResourceRecords {
		err = writeDomainName(responseBuffer, additionalResourceRecord.DomainName)

		if err != nil {
			log.Fatal("Error writing to buffer: %v", err.Error())
		}

		Write(responseBuffer, additionalResourceRecord.Type)
		Write(responseBuffer, additionalResourceRecord.Class)
		Write(responseBuffer, additionalResourceRecord.TimeToLive)
		Write(responseBuffer, additionalResourceRecord.ResourceDataLength)
	}
	_, err = udpConn.WriteToUDP(responseBuffer.Bytes(), addr)
	if err != nil {
		log.Fatal("write response data failed!,error: %v", err)
	}
}

func main() {
	log.Printf("service bind to port:%d,start Listen DNS request.....\n", port)
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(serverAddr), Port: port})
	if err != nil {
		log.Fatal("Listen faied!,%s", err)
		return
	}
	defer udpConn.Close()
	for {
		data := make([]byte, UDPMaxMessageSizeBytes)
		_, addr, err := udpConn.ReadFromUDP(data)
		if err != nil {
			log.Fatal("Read from udp stream:%s failed,err:%v", addr, err)
			break
		}
		go handleDNSRequest(udpConn, addr, data)
	}
}

// func HttpManager() {
//     http.Handle("/")
// 	err := http.ListernAndServe(":8000", nil)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// }

// func main() {
// 	go DNSResourceRecord()
// 	// go HttpManager()
// }
