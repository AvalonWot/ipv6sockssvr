package main

import (
	"fmt"
	"net"
	"syscall"
	"time"
)

type TcpWithMarkDialer struct {
	Mark int
}

func (d *TcpWithMarkDialer) Dial(network, addr string) (net.Conn, error) {
	dialer := net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			var sockErr error
			// The control function will be executed after the socket is created and before connect
			err := c.Control(func(fd uintptr) {
				sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, d.Mark)
				if sockErr != nil {
					fmt.Printf("setsockopt SO_MARK failed: %v\n", sockErr)
				}
			})
			if err != nil {
				return err
			}
			return sockErr
		},
	}
	return dialer.Dial(network, addr)
}
