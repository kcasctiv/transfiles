package main

import (
	"flag"
	"fmt"
	"net"

	"github.com/kcasctiv/transfiles"

	"github.com/sirupsen/logrus"
)

func main() {
	var port int
	flag.IntVar(&port, "port", 13666, "listening port")

	flag.Parse()

	addr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		logrus.WithError(err).Fatal("could not resolve tcp address")
	}
	ln, err := net.ListenTCP("tcp", addr)
	if err != nil {
		logrus.WithError(err).Fatal("could not listen tcp")
	}

	for {
		if conn, err := ln.AcceptTCP(); err == nil {
			go func(c net.Conn) {
				defer c.Close()

				transfiles.Receive(c)
			}(conn)
		}
	}
}
