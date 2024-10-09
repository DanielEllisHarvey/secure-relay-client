# secure-relay-client

An overcomplicated and over-implemented secure messaging client, made in native javascript using the Web Crypto API

## Server and client

### Client

The client is made of a HTML document, (which because of browser security) cannot be hosted over HTTP, but can be hosted with HTTPS; the browser unsets `window.crypto` entirely over an insecure HTTP connection, but will run fine if opened as a file.

> The client is written in JavaScript (or ECMAscript) without external plugins or libraries.

### Server

The server is a python server running FastAPI WebSocket. WebSockets are used because they provide a persistent connection between client and server, but they are also used to circumvent CORS restrictions on non-hosted files in the browser.

> Get requests can't be used on files that aren't hosted over HTTP (to my knowledge), but WebSockets have no problems.

To verify the connection's key, the server's public key is sent over WS (to derive a shared secret using ECDH), as well as some randomly generated bytes. The shared key is used as a HMAC key to sign the random bytes, which are sent back to the server. If the signature matches the server's, then the server can trust the connection is authentic.

### Running the server
```
# Arch linux
sudo pacman -S python3 python-virtualenv

# Debian
sudo apt install python3 python3.12-venv

python3 -m venv env
source env/bin/activate
pip install fastapi[standard] websockets pyca cryptography
fastapi run ws-server.py --port 8080
```

### Message delivery

When a message is sent from the client, the server checks the list of connected WebSockets for the user ID associated with the websocket connection. If the ID can be found, the message is forwarded. If the ID can't be found, the server will tell the client that the user can't be found.

When the other client connects, a "hello" is sent to the server, where it is forwarded to the other client. When a client receives a hello, it sends all cached messages to the other client, who is now online and ready.

## Cryptography

### Initialization of keys

When a client uses the key of an external user, the client will generate a number of keys for different purposes:

- 2048 bit HMAC signing/derivation key
- 256 bit PBKDF2 derivation key
- 256 bit AES-GCM symmetric encryption key
- 32 bit salt modulation value

The reason for the salt modulating value is to create instance-specific pseudo-random numbers (which are the same between the two parties).

The HMAC key is used to both sign message data for integrity purposes, and to provide values to modify the bits of the PBKDF2 key. There is no reason it has to be 256 Bytes, other than to make the key more secure (which seems of dubious efficacy), but the length doesn't seem to have a significant impact on performance.

### Encryption

All encryption is done with AES-GCM, since it seems to be more widely recognized as standard and secure. Key exchanges are done with ECDH, which would've been Curve25519 if Chrome had compatibility for it.

### Signatures

Because of the construction of the system, message signatures are not necessary. A shared secret is made with a private and public key, which proves ownership of the private key, if the user didn't have access to the private key, they wouldn't be able to generate the shared secret, and wouldn't be able to encrypt or decrypt messages.
