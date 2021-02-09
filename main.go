package main

import (
	"errors"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	log "github.com/sirupsen/logrus"
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

// RFC 5575
// 0x8006, traffic-rate, 2-byte as#, 4-byte float
// 0x8007, traffic-action, bitmask
// 0x8008, redirect, 6-byte Route Target
// 0x8009, traffic-marking, DSCP value
const (
	ActionTrafficRate    = 0x8006
	ActionTrafficAction  = 0x8007
	ActionRedirect       = 0x8008
	ActionTrafficMarking = 0x8009
)

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
	//goland:noinspection ALL
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

// parseCommunity parses a BGP community string into a flowspec action and attribute
func parseFlowCommunity(input string) (int64, int64, error) {
	parts := strings.Split(input, ", ")
	if len(parts) != 3 {
		return -1, -1, errors.New("invalid community string")
	}

	// Parse action as int
	actionPart := strings.TrimSuffix(parts[1], "0000")
	action, err := strconv.ParseInt(actionPart, 0, 64)
	if err != nil {
		return -1, -1, errors.New("invalid community string: " + err.Error())
	}

	// Validate action
	if !(action == ActionTrafficRate || action == ActionTrafficAction || action == ActionRedirect || action == ActionTrafficMarking) {
		return -1, -1, errors.New("invalid flowspec action")
	}

	// Parse argument as int
	argPart := strings.TrimSuffix(parts[2], "0000")
	arg, err := strconv.ParseInt(argPart, 0, 64)
	if err != nil {
		return -1, -1, errors.New("invalid community string: " + err.Error())
	}

	return action, arg, nil // nil error
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

// arrayIncludes runs a linear search on a string array
func arrayIncludes(arr []string, elem string) bool {
	for _, item := range arr {
		if item == elem {
			return true
		}
	}
	return false
}

func main() {
	log.SetLevel(log.DebugLevel)

	// Get iptables object
	iptab, err := iptables.New()
	if err != nil {
		log.Fatal(err)
	}

	// Check if the flowspec filter chain exists
	chains, err := iptab.ListChains("filter")
	if err != nil {
		log.Fatal(err)
	}
	if !arrayIncludes(chains, "FLOWSPEC") {
		log.Debug("iptables chain FLOWSPEC doesn't exist, creating.")
		err = iptab.NewChain("filter", "FLOWSPEC")
		if err != nil {
			log.Fatal(err)
		}
	} else {
		log.Debug("iptables chain FLOWSPEC exists")
	}

	for _, flowRoute := range strings.Split(birdCommand("show route where (net.type = NET_FLOW4 || net.type = NET_FLOW6) all"), "flow") {
		// Ignore lines that aren't a valid IPv4/IPv6 flowspec route
		if !(strings.HasPrefix(flowRoute, "4") || strings.HasPrefix(flowRoute, "6")) {
			continue
		}

		parts := strings.Split(flowRoute, "\n")

		header := "flow" + parts[0]
		localSessionAttrs, err := parseSessionAttrs(inclusiveMatch(header, "[", "]"))
		if err != nil {
			log.Printf("invalid flowspec route: (%s): %v\n", header, err)
			continue
		}

		localMatchAttrs, err := parseMatchAttrs(inclusiveMatch(header, "{ ", " }"))
		if err != nil {
			log.Printf("invalid flowspec route: (%s): %v\n", header, err)
			continue
		}

		action, arg, err := parseFlowCommunity(inclusiveMatch(flowRoute, "BGP.ext_community: (", ")"))
		if err != nil {
			log.Printf("invalid flowspec route: (%s): %v\n", header, err)
			continue
		}

		log.Printf("%+v %+v (%d %d)\n", localSessionAttrs, localMatchAttrs, action, arg)
	}
}
