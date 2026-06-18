// Go echo client. Opens N goroutines (one per connection), each
// runs `rounds` ping-pong cycles. Prints client-side rt/s.

package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

func main() {
	if len(os.Args) < 5 {
		fmt.Fprintln(os.Stderr, "usage: client <port> <conns> <rounds> <payload>")
		os.Exit(2)
	}
	port, _ := strconv.Atoi(os.Args[1])
	conns, _ := strconv.Atoi(os.Args[2])
	rounds, _ := strconv.Atoi(os.Args[3])
	payload, _ := strconv.Atoi(os.Args[4])

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	msg := make([]byte, payload)
	for i := range msg {
		msg[i] = 0x42
	}

	// Open all connections up-front so the timed loop measures
	// steady-state I/O, not connect overhead.
	sockets := make([]net.Conn, conns)
	for i := 0; i < conns; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "dial:", err)
			os.Exit(1)
		}
		sockets[i] = c
	}

	var wg sync.WaitGroup
	t0 := time.Now()
	for i := 0; i < conns; i++ {
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			buf := make([]byte, payload)
			for r := 0; r < rounds; r++ {
				if _, err := c.Write(msg); err != nil {
					return
				}
				if _, err := io.ReadFull(c, buf); err != nil {
					return
				}
			}
		}(sockets[i])
	}
	wg.Wait()
	elapsed := time.Since(t0)

	rate := float64(rounds*conns) / elapsed.Seconds()
	fmt.Printf("go: %d conns x %d rounds @ %d B → %d rt/s\n",
		conns, rounds, payload, int(rate))

	for _, c := range sockets {
		c.Close()
	}
}
