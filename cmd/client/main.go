package main

import (
	"flag"
	"net"

	"github.com/kcasctiv/transfiles"
	"github.com/sirupsen/logrus"
)

func main() {
	var url string
	var file string
	flag.StringVar(&url, "url", "localhost:13666", "server url")
	flag.StringVar(&file, "file", "", "name of a file to transfer")

	flag.Parse()

	addr, err := net.ResolveTCPAddr("tcp", url)
	if err != nil {
		logrus.WithError(err).Fatal("could not resolve url address")
	}

	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		logrus.WithError(err).Fatal("could not dial tcp")
	}
	defer conn.Close()

	transfiles.Send(file, conn)
}
