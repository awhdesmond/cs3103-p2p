# cs3103-p2p
CS3103 Project

## Setup and Requirements
 1. Install __python 3__ and __pip3__ on your local development pc.
 2. `git clone` the current repo
 3. `pip3 install virtualenv`
 4. `source /cs3103-env/bin/activate`
 5. Start developing
 
Please start an instance of the dns server first by running `python3 p2pdns.py`

To start an instance of the p2p node, run:
`python3 p2pmain.py 127.0.X.X`

> If you ever download a third-party python library, remember to `pip3 freeze > requirements.txt` to update the dependencies list.

## Testing
  1. Install Vagrant and Virtualbox
  2. `cd` to the directory
  3. `vagrant up` and wait for it to initialise
  4. `vagrant ssh dns/alpha/beta/charlie/delta/echo` into either vm.
  5. To transfer file, run `vagrant config-ssh` to check the port of the vm
  6. cd to parent dir and `sudo scp -P <PORT> -i ./cs3103-p2p/.vagrant/machines/<VM NAME>/virtualbox/private_key -r cs3103-p2p/ vagrant@127.0.0.1:/home/vagrant`
  7. Run `p2pdns.py` in `dns` vm.
  8. Run `p2pmain.py` in the other peers


## Components

### P2P DNS
P2P DNS server serves as a introducer whenever a new peer wants to join the network. The information is stored in a __sqlite3 db__.

### P2P Main
This the the main program that the user will run. It is a wrapper for __P2P Client__ and __P2P Server__. __P2P Client__ will handle the various user interactions. __P2P Server__ will handle file uploading, file downloading and DHT queries. __P2P Client__ will communicate with __P2P Server__ using __Unix Domain Sockets (UDS)__ while the communication between __P2P Server__ of different peer will be done using standard TCP sockets. 


## Application layer Protocols:
The different protocols implemented provides a systematic manner for different components to communicate with each other. Furthermore, since we are using TCP Byte Stream sockets, we need a way to delimit where our messages end. Hence -- protocols.

### P2P Client - P2P DNS
#### Requests
General Format: `op` `[...args]\r\n`
  
  1. `JOIN <peer_id> <ip-addr>`

#### Responses
General Format: 

`code` `message` `content-length\r\n`<br/>
dataline...`\r\n`<br/>
dataline...`\r\n`


### P2P Server - P2P Server
General Format: `op` `[...args]\r\n`

#### Node Joining Network
  1. `GET_NEIGHBOURS <node_id> <node_ip_addr>`
  2. `RET_NEIGHBOURS <predecessor_id> <predecessor_ip_addr> <successor_id> <successor_ip_addr> <next_successor_id> <next_succcessor_ip_addr>`
  3. `UPDATE_NEXT_SUCCESSOR <next_successor_id> <next_succcessor_ip_addr>`
  4. `UPDATE_PREDECESSOR <predecessor_id> <predecessor_ip_addr>`

#### Requests
  
  1. `INIT_PEER_TABLE`
  2. `LIST_ALL_FILES`
  3. `SEARCH <filename>`
  4. `DOWNLOAD <filename>`
  5. `UPLOAD <filename>`

#### Responses
General Format: 

`code` `message` `content-length\r\n`<br/>
dataline...`\r\n`<br/>
dataline...`\r\n`


## References
https://realpython.com/python-sockets/

https://pymotw.com/3/socket/uds.html