package main

import (
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
)

var birdSocket = "/run/bird/bird.ctl"

type matchAttrs struct {
	Source          net.IPNet
	Destination     net.IPNet
	SourcePort      uint16
	DestinationPort uint16
}

type sessionAttrs struct {
	SessionName     string
	NeighborAddress net.IP
	ImportTime      string
}

// Buffered io Reader
func bufferedRead(reader io.Reader) string {
	log.Println("Reading from BIRD socket")
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 32)
	for {
		n, err := reader.Read(tmp)
		if err != nil {
			log.Fatalf("read error: %s\n", err)
		}
		buf = append(buf, tmp[:n]...)

		if strings.Contains(string(tmp), "0000 \n") {
			return string(buf)
		}
	}
}

func birdCommand(command string) string {
	log.Println("Connecting to BIRD socket")
	conn, err := net.Dial("unix", birdSocket)
	if err != nil {
		log.Fatalf("BIRD socket connect: %v", err)
	}
	defer conn.Close()

	log.Println("Connected to BIRD socket")
	//connResp := bufferedRead(conn)
	//if !strings.HasSuffix(connResp, "ready.\n") {
	//	log.Fatalf("BIRD connection response: %s", connResp)
	//}

	log.Printf("Sending BIRD command: %s", command)
	_, err = conn.Write([]byte(strings.Trim(command, "\n") + "\n"))
	log.Printf("Sent BIRD command: %s", command)
	if err != nil {
		log.Fatalf("BIRD write error: %s\n", err)
	}

	return bufferedRead(conn)
}

func inclusiveMatch(input string, leftDelimiter string, rightDelimiter string) string {
	leftSide := strings.Split(input, leftDelimiter)
	if len(leftSide) < 2 {
		return ""
	}

	return strings.Split(leftSide[1], rightDelimiter)[0]
}

func parseMatchAttrs(input string) (matchAttrs, error) {
	var outputMatchAttrs = matchAttrs{}
	for _, kvPair := range strings.Split(input, ";") {
		parts := strings.Split(strings.TrimRight(strings.TrimLeft(kvPair, " "), " "), " ")
		if len(parts) > 1 {
			key := strings.TrimSpace(strings.Join(parts[:len(parts)-1], "_"))
			value := strings.TrimSpace(parts[len(parts)-1])
			switch key {
			case "src":
				_, localSource, err := net.ParseCIDR(value)
				if err != nil {
					return matchAttrs{}, errors.New("unable to parse source prefix")
				}
				outputMatchAttrs.Source = *localSource
			case "dst":
				_, localDestination, err := net.ParseCIDR(value)
				if err != nil {
					return matchAttrs{}, errors.New("unable to parse destination prefix")
				}
				outputMatchAttrs.Destination = *localDestination
			case "sport":
				localSPort, err := strconv.Atoi(value)
				if err != nil {
					return matchAttrs{}, errors.New("unable to parse source port")
				}
				outputMatchAttrs.SourcePort = uint16(localSPort)
			case "dport":
				localDPort, err := strconv.Atoi(value)
				if err != nil {
					return matchAttrs{}, errors.New("unable to parse destination port")
				}
				outputMatchAttrs.DestinationPort = uint16(localDPort)
			}
		}
	}

	return outputMatchAttrs, nil // nil error
}

// parseSessionAttrs parses the BIRD session attributes
func parseSessionAttrs(input string) (sessionAttrs, error) {
	var outputSessionAttrs = sessionAttrs{}

	parts := strings.Split(input, " ")
	if len(parts) != 4 {
		return sessionAttrs{}, errors.New("invalid token length")
	}

	// Set string values
	outputSessionAttrs.SessionName = parts[0]
	outputSessionAttrs.ImportTime = parts[1]

	ip := net.ParseIP(parts[3])
	if ip == nil {
		return sessionAttrs{}, errors.New("invalid neighbor IP address")
	}

	outputSessionAttrs.NeighborAddress = ip

	return outputSessionAttrs, nil // nil error
}

func main() {
	flowRoutes := ""
	for _, line := range strings.Split(birdCommand("show route where (net.type = NET_FLOW4 || net.type = NET_FLOW6) all"), "\n") {
		if strings.Contains(line, "flow4") || strings.Contains(line, "flow6") {
			flowRoutes += line + "|"
		}
	}

	// Remove trailing route delimiter
	flowRoutes = strings.TrimSuffix(flowRoutes, "|")

	for _, route := range strings.Split(flowRoutes, "|") {
		localSessionAttrs, err := parseSessionAttrs(inclusiveMatch(route, "[", "]"))
		if err != nil {
			log.Printf("invalid flowspec route: (%s): %v\n", route, err)
		}

		localMatchAttrs, err := parseMatchAttrs(inclusiveMatch(route, "{ ", " }"))
		if err != nil {
			log.Printf("invalid flowspec route: (%s): %v\n", route, err)
		}

		log.Println(localSessionAttrs, localMatchAttrs)
	}
}
