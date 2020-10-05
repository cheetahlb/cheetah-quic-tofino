# Comparison Stateless Cheetah with QUIC with simple hash LB: P4-Tofino code

We compare Stateless QUIC-base Cheetah with a simple hash-based LB. The testbed is identical to the above parent directory except that we use four buckets with a ratio of 3:1 between the two servers.

## Code organization

The code consists of four files:

 * `cheetah_quic_and_hash_pipeline.p4`, which contains the P4 program to handle either Cheetah QUIC cookies or perform a simple LB.
 * `cheetah_and_hash_setup.py`, which contains the Python commands to populate the P4 switch.
 * `cheetah_change_mode_to_wrr.py`, which allows to enable the Cheetah Weighted Round Robin (WRR) LB.
 * `cheetah_change_mode_to_hash.py`, which allows to enable a simple hash-based LB.

## Prerequisites

You should have installed our modified version of picoquic (from [here](link)) on three machines. One machine is used as a cliente and two machines as the servers.

## Topology and configuration

The `VIP` of Cheetah is preconfigured to be `192.168.64.1`

The `DIP` of Server-1 is preconfigured to be `192.168.63.16`. Server-1 is connected to port 10 (D_P = 52) of the Tofino switch.
The `DIP` of Server-2 is preconfigured to be `192.168.63.19`. Server-2 is connected to port 13 (D_P = 28) of the Tofino switch.

The client is connected to port 9 (D_P = 60) of the tofino switch.

The current P4 program does not handle ARP requests so ARP should be statically set up on the machines and the MAC addresses should be configured in the `cheetah_and_hash_setup.py` file.

The LB implementes Weighted Round Robin with 4 buckets. Two first three buckets map to Server-1 and the last bucket to Server-2.

If you plan to change these values, you need to modify them in the `cheetah_and_hash_setup.py` file.

## Running the code

Move the files of this repository on a folder

`scp cheetah* username@host:$CHEETAH_LAB`

where `$CHEETAH_LAB` is the directory where you plan to store the tofino-related files and host is the IP of the Tofino switch.

### Build the program

`$SDE/p4_build.sh $CHEETAH_LAB/cheetah_quic_and_hash_pipeline.p4`

### Run the program

Run the program onto the switch:

`$SDE/run_switchd.sh -p cheetah_quic_and_hash_pipeline`

### Populate the table and registers

Run in another window the following commands:

`$SDE/run_bfshell.sh -b $CHEETAH_LAB/cheetah_and_hash_setup.py`

Ths switch is now running properly.

## Test the load balancer

Prerequisites: generate a file to be fetched by the client and put it into `server_files/index.html` subdirectory of the picoquic directory where you will run the following commands. Also create a directory `client_files` where the fetched file will be stored.

Initially the LB has the Cheetah cookie enabled.

Go to Server-1 and run the following command:

`./picoquic_sample server 4433 ./certs/ca-cert.pem ./certs/server-key.pem ./server_files 1`

Go to Server-2 and run the following command:

`./picoquic_sample server 4433 ./certs/ca-cert.pem ./certs/server-key.pem ./server_files 2`

Open three `tcpdump` sessions to spoof traffic at the interfaces of the three machines.

### Test the Cheetah LB

Go to the client and run the following command:

`./picoquic_sample client 192.168.64.1 4433 ./client_files index.html`

This will generate a request towards the `VIP` and will be served by Server-1. Check on `tcpdump`.

Run again the same command at the client. The request will again be served by Server-1. Check on `tcpdump`

Run again the same command at the client. The request will again be served by Server-1. Check on `tcpdump`

Run again the same command at the client. The request will now be served by Server-2. Check on `tcpdump`

This cycle repeats for each request sent by a client.

### Test the simple hash-based LB

In the window where you ran the `run_bfshell` command, execute this command:

`$SDE/run_bfshell.sh -b $CHEETAH_LAB/cheetah_change_mode_to_hash.py`

This will enable the simple hash-based LB.

Repeat the above commands many time. You will see that the connection will be load balanced roughly in a 3:1 ratio.
