# Stateless Cheetah with QUIC: P4-Tofino code

We implemented Stateless Cheetah in P4 on the Tofino to load balancer QUIC connections by storing the Cheetah cookie in the connection ID of the QUIC packet headers.

## Code organization

The code consists of two files:

 * `cheetah_quic_pipeline.p4`, which contains the P4 program to handle Cheetah cookies.
 * `cheetah_setup.py`, which contains the Python commands to populate the P4 switch.
 * `comparison_with_simple_hash/`, contains the cheetah quic pipeline and a simple hash-based LB for comparing them.

## Prerequisites

You should have installed our modified version of picoquic (from [here](link)) on three machines. One machine is used as a cliente and two machines as the servers.

## Topology and configuration

The `VIP` of Cheetah is preconfigured to be `192.168.64.1`

The `DIP` of Server-1 is preconfigured to be `192.168.63.16`. Server-1 is connected to port 10 (D_P = 52) of the Tofino switch.
The `DIP` of Server-2 is preconfigured to be `192.168.63.19`. Server-2 is connected to port 13 (D_P = 28) of the Tofino switch.

The client is connected to port 9 (D_P = 60) of the tofino switch.

The current P4 program does not handle ARP requests so ARP should be statically set up on the machines and the MAC addresses should be configured in the `cheetah_setup.py` file.

The LB implementes Weighted Round Robin with 3 buckets. Two first two buckets map to Server-1 and the last bucket to Server-2.

If you plan to change these values, you need to modify them in the `cheetah_setup.py` file.

## Running the code

Move the files of this repository on a folder

`scp cheetah* username@host:$CHEETAH_LAB`

where `$CHEETAH_LAB` is the directory where you plan to store the tofino-related files and host is the IP of the Tofino switch.

### Build the program

`$SDE/p4_build.sh $CHEETAH_LAB/cheetah_quic_pipeline.p4`

### Run the program

Run the program onto the switch:

`$SDE/run_switchd.sh -p cheetah_quic_pipeline`

### Populate the table and registers

Run in another window the following commands:

`$SDE/run_bfshell.sh -b $CHEETAH_LAB/cheetah_setup.py`

Ths switch is now running properly.

## Test the load balancer

Prerequisites: generate a file to be fetched by the client and put it into `server_files/index.html` subdirectory of the picoquic directory where you will run the following commands. Also create a directory `client_files` where the fetched file will be stored.

Go to Server-1 and run the following command:

`./picoquic_sample server 4433 ./certs/ca-cert.pem ./certs/server-key.pem ./server_files 1`

Go to Server-2 and run the following command:

`./picoquic_sample server 4433 ./certs/ca-cert.pem ./certs/server-key.pem ./server_files 2`

Open three `tcpdump` sessions to spoof traffic at the interfaces of the three machines.

Go to the client and run the following command:

`./picoquic_sample client 192.168.64.1 4433 ./client_files index.html`

This will generate a request towards the `VIP` and will be served by Server-1. Check on `tcpdump`.

Run again the same command at the client. The request will again be served by Server-1. Check on `tcpdump`

Run again the same command at the client. The request will now be served by Server-2. Check on `tcpdump`

This cycle repeats for each request sent by a client.

