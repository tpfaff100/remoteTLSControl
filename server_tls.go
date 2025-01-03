/* server_tls written 1/2024 by Thomas Pfaff
   
   Usage:

   Generate certs to allow TLS/SSL socket usage:

------------------
Using OPENSSL, generate an https key so we can run an https server easily:
openssl genrsa 2048 > server.key
chmod 400 server.key
openssl req -new -x509 -nodes -sha256 -days 365 -key server.key -out server.crt
-------------------

   go build tls_server.go
   go build tls_client.go
   ./tls_server
   (follow the instructions to run it again as sudo)
   open another terminal shell and run 
   ./tls_client

   It's that simple!
*/

package main

import (
	"log"
	"fmt"
	"crypto/tls"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"os/user"
	"bufio"
	"strings"
	"syscall"
)

const SERVER_TLS_MAJOR = 1
const SERVER_TLS_MINOR = 1
const SERVER_TLS_TLSPORT = "5555"
const SERVER_TLS_RELEASE = "alpha"

const SERVER_TLS_NO_PROBLEM_MSG = "ok."
const SERVER_TLS_TEST_FAILED_MSG = "TestFailed"

func isRoot() (string, bool) {
	currentUser, err := user.Current()
	if err != nil {
		log.Fatalf("[isRoot] Unable to get current user: %s", err)
	}
	return currentUser.Username, currentUser.Username == "root"
}


func main() {
	log.SetFlags(log.Lshortfile)

	user := tls_pipe_cmd("env | grep SUDO | grep USER | cut -d'=' -f2", true)

	if user != SERVER_TLS_NO_PROBLEM_MSG {	/* username is returned if running as sudo */
		cer, err := tls.LoadX509KeyPair("server.crt", "server.key")
		if err != nil {
			log.Println(err)
			return
		}

		config := &tls.Config{Certificates: []tls.Certificate{cer}}
		ln, err := tls.Listen("tcp", ":"+SERVER_TLS_TLSPORT, config)
		if err != nil {
			log.Println(err)
			return
		}

		defer ln.Close()

		for {
			conn, err := ln.Accept()
			if err!= nil {
				log.Println(err)
				continue
			}
			go handleConnection(conn)
		}
	} else {
		tls_banner()
	}
}



func tls_pipe_cmd(unixcmd string, quiet bool)  string {
	cmd := exec.Command("/bin/sh", "-c", unixcmd)
	r, err := cmd.StdoutPipe()
	tls_check(err)
	err = cmd.Start()
	tls_check(err)
	out, err := ioutil.ReadAll(r)
	tls_check(err)
	
	err = cmd.Wait()
	errCode := 0
	
	if (err != nil) {
		var waitStatus syscall.WaitStatus
		if exitErr, ok := err.(*exec.ExitError); ok {
			waitStatus = exitErr.Sys().(syscall.WaitStatus)
			errCode = waitStatus.ExitStatus()
		}
	}

	result := string(out)

	if quiet == false {
		print_date()
		fmt.Println("  " + strings.Trim(unixcmd, "\n") )
	}
	if len(result) == 0 {
		result = "ok."
	}

	if errCode > 1 {
		result = fmt.Sprintf("%s.  OS return code = %d\n", SERVER_TLS_TEST_FAILED_MSG, errCode)
	} else if len(result) == 0 {
		result = SERVER_TLS_NO_PROBLEM_MSG
	}
	if quiet == false {
		fmt.Println(result+"\n")
	}
	return result
}


func tls_check(err error) {
	if (err != nil) {
		log.Fatalln(err)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)

	cmd_inc, err := r.ReadString('\n')	// get cmd from client that is connected.
	if err != nil {
		log.Println(err)
		return
	}

	msg_out := tls_pipe_cmd(cmd_inc, false)
	n, err := conn.Write([]byte(msg_out+"\n"))
	n, err = conn.Write([]byte(cmd_inc+"\n"))

	if err != nil {
		log.Println(n, err)
		return
	}
}

func print_date() {
	out, err := exec.Command("date").Output()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s", strings.Trim(string(out), "\n"))
}

func tls_banner() {

	user, _ := isRoot()
	fmt.Println("\nWelcome to sudo runner over tls!")
	fmt.Println("\n  Best not to run this unless you're familiar with root access, etc")
	fmt.Printf("\n  Run this as admin - \nLINUX:  sudo -r %s %s \nMACOS:  sudo -u %s %s\n\n", user, os.Args[0], user, os.Args[0])
}



