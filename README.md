# sike-nc
Simple console communicator like netcat with Supersingular Isogeny Key Encapsulation and AES 
message encryption.

This program uses SIKEp751 implementation from https://github.com/microsoft/PQCrypto-SIDH
as a dynamic library that was created with command:

`gcc -fPIC -std=gnu11 -D _X86_ -D __NIX__ -D _GENERIC_ -shared  -o lib751.so P751/P751.c P751/generic/fp_generic.c random/random.c sha3/fips202.c`

## usage
The first person must run program as server:

`python3 sike_nc.py -l -p <server_port>`

And second person connect as a client with:

`python3 sike_nc.py <IPv4 addres> <server_port>`

To see more details about key exchange user --log DEBUG
To disable key exchange and massage encryption use --no-secure flag

## docker
#### build image
`docker build -t sike_nc_image .`
#### run on linux
server: 
`docker run -it --network=host --expose <server_port> sike_nc_image bash`

client: 
`docker run -it --network=host sike_nc_image bash`

#### run on Windows/MacOS
For running both containers that will enable to communicate with each other on Windows or MacOS use following command to create a network:

`docker network create sike_nc_network`

and then run containers with commands:

server: 
`docker run -it  --expose <server_port> --network=sike_nc_network --name sike_nc_server sike_nc_image bash`

client: 
`docker run -it --network=sike_nc_network  --name sike_nc_client sike_nc_image bash`

