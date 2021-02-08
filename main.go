package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"strings"
)

var birdSocket = "/run/bird/bird.ctl"

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

func main() {
	flowRoutes := birdCommand("show route where (net.type = NET_FLOW4 || net.type = NET_FLOW6) all")
	routes := strings.Split(flowRoutes, "{ ")
	for _, route := range routes {
		fmt.Println(route)
		fmt.Println("----")
	}
}
