# sike-nc
Simple console communicator like netcat with Supersingular Isogeny Key Encapsulation and AES 
message encryption.

This program uses SIKEp751 implementation from https://github.com/microsoft/PQCrypto-SIDH
as a dynamic library. The x64_fast library was created in /Additional_Implementations/x64/SIKEp751/ directory with command:

`gcc -fPIC -std=gnu11 -D __LINUX__ -D _OPTIMIZED_FAST_ -D _AMD64_ -shared -o lib751_x64.so P751.c AMD64/fp_x64.c AMD64/fp_x64_asm.S random/random.c sha3/fips202.c`


## usage
The first person must run program as server:

`python3 sike_nc.py -l -p <server_port>`

And second person connect as a client with:

`python3 sike_nc.py <IPv4 addres> <server_port>`

To see more details about key exchange user `--log DEBUG`
To disable key exchange and massage encryption use `--no-secure` flag

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

