<pre>server_tls written 1/2025 by Thomas Pfaff

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
</pre>
