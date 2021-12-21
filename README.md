# VPN Project assignment
The goal of this project is to create an encrypted VPN tunnel between two hosts.
There are 2 parts of in this repo. ForwardClient and ForwardServer, the names are self-explanatory.
Run ForwardServer via example `java ForwardServer --handshakeport=2206 --usercert=server.pem --cacert=ca.pem --key=server-private.der` specifying the appropriate paths to the certificates.
Then launch ForwardClient using `java ForwardClient --handshakehost=portfw.kth.se  --handshakeport=2206 --proxyport=54321 --targethost=time.nist.gov --targetport=13 --usercert=client.pem --cacert=ca.pem --key=client-private.der` as an example.
The client will try to establish a handshake with the server, which will in return create a session host and port for the secure session and provide these details to the client. Which will wait for the user to connect to the proxy port in order to transfer the data to the desired server.
In order for this to work, appropriate certificates needed to be present - the CA certificate and client and server certs. cigned by the CA. This was done using openssl.
