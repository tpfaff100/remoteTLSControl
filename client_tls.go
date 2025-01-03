/* Thomas Pfaff, 1/2024

   Client-Server remote control demo of SUDO using TLS sockets.
   Yeah, you like totally want to do this, dont you?
   Elegant in its simplicity.

   (i.e. please understand the risks/security hole you're opening up!)

   Directions are in server_tls.go
*/

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"

)

func main() {
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if (err != nil) {
		log.Fatalf("server: loadkeys: %s", err)
	}

	config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}

	conn, err := tls.Dial("tcp", "localhost:5555", &config)
	if err != nil {
		log.Fatalf("client: dial %s\n", err)
	}

	defer conn.Close()

	log.Println("client connected to: ", conn.RemoteAddr())

	state := conn.ConnectionState()

	for _, v := range state.PeerCertificates {
		fmt.Println("Client: Server public key is: ")
		fmt.Println(x509.MarshalPKIXPublicKey(v.PublicKey))
	}

	log.Println("client: handshake: ", state.HandshakeComplete)
	log.Println("client: mutual: ", state.NegotiatedProtocolIsMutual)

	message := "ls -l\n"
	n, err := io.WriteString(conn, message)
	if err != nil {
		log.Fatalf("client: write %s", err)
	}

	log.Printf("Client: wrote %q (%d bytes) ", message, n)
	reply := make([]byte, 256)

	n, err = conn.Read(reply)
	log.Printf("client: read %q (%d bytes)", string(reply[:n]), n)
	log.Print("client: exiting")
}

