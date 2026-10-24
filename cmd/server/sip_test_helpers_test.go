package main

import (
	"net"
	"testing"

	"github.com/emiago/sipgo"
)

func serveTestSIPUDP(t *testing.T, server *sipgo.Server, address string) {
	t.Helper()
	connection, err := net.ListenPacket("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	go func() { _ = server.ServeUDP(connection) }()
}
