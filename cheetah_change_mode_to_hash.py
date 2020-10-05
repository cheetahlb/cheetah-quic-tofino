from ipaddress import ip_address
import sys
import csv

p4 = bfrt.cheetah_quic_and_hash_pipeline.pipe

# initialize the registers
lb_mode_reg = p4.Ingress.lb_mode_reg
lb_mode_reg.mod(register_index=0, f1=1)

lb_mode_reg.dump(from_hw=1)
