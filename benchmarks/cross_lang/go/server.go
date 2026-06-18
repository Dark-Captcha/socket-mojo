// Go echo server: net stdlib, goroutine per connection, plain
// blocking read/write. The pattern Go developers actually use.
// Underlying I/O is epoll via the runtime's netpoll.
//
// Run: go run server.go <port> <conns>

package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: server <port> <conns>")
		os.Exit(2)
	}
	port, _ := strconv.Atoi(os.Args[1])
	totalConns, _ := strconv.Atoi(os.Args[2])

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}

	var wg sync.WaitGroup
	for i := 0; i < totalConns; i++ {
		c, err := ln.Accept()
		if err != nil {
			fmt.Fprintln(os.Stderr, "accept:", err)
			break
		}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer c.Close()
			buf := make([]byte, 16384)
			for {
				n, err := c.Read(buf)
				if n > 0 {
					_, werr := c.Write(buf[:n])
					if werr != nil {
						return
					}
				}
				if err != nil {
					if err != io.EOF {
						// silent — client closes on completion
					}
					return
				}
			}
		}(c)
	}
	ln.Close()
	wg.Wait()
}
