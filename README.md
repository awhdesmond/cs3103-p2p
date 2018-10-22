# cs3103-p2p
CS3103 Project

## Setup and Requirements
 1. Install __python 3__ and __pip3__ on your local development pc.
 2. `git clone` the current repo
 3. `pip3 install virtualenv`
 4. `source /cs3103-env/bin/activate`
 5. Start developing

> If you ever download a third-party python library, remember to `pip3 freeze > requirements.txt` to update the dependencies list.

## Components

### P2P DNS
P2P DNS server serves as a introducer whenever a new peer wants to join the network. 

### P2P Main
This the the main program that the user will run. It is a wrapper for __P2P Client__ and __P2P Server__. __P2P Client__ will handle the various user interactions. __P2P Server__ will handle file uploading, file downloading and DHT queries. __P2P Client__ will communicate with __P2P Server__ using Unix Domain Sockets (UDS) while the communication between __P2P Server__ of different peer will be done using standard TCP sockets. 

## Application layer Protocols:
The different protocols implemented provides a systematic manner for different components to communicate with each other. Furthermore, since we are using TCP Byte Stream sockets, we need a way to delimit where our messages end. Hence -- protocols.

### P2P Client - P2P DNS

### P2P Server - P2P Server


## References
https://realpython.com/python-sockets/

https://pymotw.com/3/socket/uds.html