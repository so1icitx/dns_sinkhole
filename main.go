package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
)

type DNSHeader struct {
	ID             uint16
	Flags          uint16
	NumQuestions   uint16
	NumAnswers     uint16
	NumAuthorities uint16
	NumAdditional  uint16
}

type DNSResponse struct {
	Pointer    uint16
	Type       uint16
	Class      uint16
	TTL        uint32
	DataLength uint16
	IPAddress  uint32
}

func main() {
	// binds the program to a port & creates a UDP listener
	udpAddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 5353}
	listener, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// a closure that checks if a domain is in the blocklist
	check := isBlocklisted()

	// regex pattern to validate domain names, compiled once so we don't exhaust CPU
	domainValidator := regexp.MustCompile(`^([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$`)

	for {

		// reading from the UDP stream and storing it into a byte slice
		data := make([]byte, 512)
		_, clientAddr, err := listener.ReadFromUDP(data)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}

		// passing data excluding the dns header portion
		requestedDomain, pointer := extractDnsData(data[12:])

		// validating input isn't bogus
		isValid := domainValidator.MatchString(requestedDomain)
		if !isValid {
			continue
		}

		// extracting original dns header to a struct
		dnsHeader := DNSHeader{}
		_, err = binary.Decode(data[:12], binary.BigEndian, &dnsHeader)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}

		// forging the response & forwarding it
		response := FinalIteration(check(requestedDomain), requestedDomain, &dnsHeader, data[12:pointer+17], data)
		listener.WriteToUDP(response, clientAddr)
	}
}

func extractDnsData(data []byte) (string, int) {
	var (
		pointer int
		domain  string
	)
	for {
		if int(data[pointer]) == 0 {
			break
		}
		tmp := string(data[pointer+1 : int(data[pointer])+pointer+1])
		pointer += int(data[pointer] + 1)
		domain = domain + tmp + "."
	}
	return domain[:len(domain)-1], pointer
}
func isBlocklisted() func(string) bool {

	blockList := make(map[string]bool)
	f, err := os.Open("blocklist.txt")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		blockList[scan.Text()] = true
	}
	return func(domain string) bool {
		domain = domain[:len(domain)]
		fmt.Println(domain)
		_, ok := blockList[domain]
		if ok {
			return true
		}
		return false
	}
}

func FinalIteration(result bool, domain string, header *DNSHeader, data []byte, originalRequest []byte) []byte {
	var networkNum uint32
	var nxDomain bool
	header.Flags = 33152
	header.NumAnswers = 1
	header.NumAdditional = 0

	// if domain is not in blocklist
	if !result {
		addr, err := ResolveDomain(domain, originalRequest)

		// if domain doesnt exist (NXDOMAIN)
		if err != nil {
			header.NumAnswers = 0
			header.Flags = 33155
			nxDomain = true
		} else {
			networkNum = binary.BigEndian.Uint32(net.ParseIP(addr).To4())
		}

	}

	response := make([]byte, 12)
	_, err := binary.Encode(response, binary.BigEndian, *header) // was & but had error fixed when added * ( took way too long to figure out lol)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	response = append(response, data...)

	// if the requested domain exists
	if !nxDomain {
		dnsResponse := DNSResponse{49164, 1, 1, 60, 4, networkNum}
		tmpResponse := make([]byte, 16)
		binary.Encode(tmpResponse, binary.BigEndian, &dnsResponse)
		response = append(response, tmpResponse...)
	}

	return response
}

func ResolveDomain(domain string, data []byte) (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return "", errors.New("err: Unable to reach endpoint")
	}
	defer conn.Close()
	conn.Write(data)
		
	rawBytes := make([]byte, 512)
	_, err = conn.Read(rawBytes)
	if err != nil {
		return "0.0.0.0", errors.New("err: Unable to read bytes from UDP stream")
	}

	// validating if the domain exists or not
	rcode := rawBytes[3] & 0x0F
	if rcode == 3 {
		return "", errors.New("NXDOMAIN")
	}

	// finding answer portion
	pointer := 12
	for {
		if !(rawBytes[pointer] == 0) {
			pointer++
		} else {
			break
		}
	}
	ipString := net.IP(rawBytes[pointer+17 : pointer+21]).String()

	return ipString, nil
}
