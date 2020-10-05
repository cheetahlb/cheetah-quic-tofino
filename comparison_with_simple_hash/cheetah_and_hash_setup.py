from ipaddress import ip_address
import sys
import csv


p4 = bfrt.cheetah_quic_and_hash_pipeline.pipe

# This function can clear all the tables and later on other fixed objects
# once bfrt support is added.
def clear_all(verbose=True, batching=True):
    global p4
    global bfrt
    
    def _clear(table, verbose=False, batching=False):
        if verbose:
            print("Clearing table {:<40} ... ".
                  format(table['full_name']), end='', flush=True)
        try:    
            entries = table['node'].get(regex=True, print_ents=False)
            try:
                if batching:
                    bfrt.batch_begin()
                for entry in entries:
                    entry.remove()
            except Exception as e:
                print("Problem clearing table {}: {}".format(
                    table['name'], e.sts))
            finally:
                if batching:
                    bfrt.batch_end()
        except Exception as e:
            if e.sts == 6:
                if verbose:
                    print('(Empty) ', end='')
        finally:
            if verbose:
                print('Done')

        # Optionally reset the default action, but not all tables
        # have that
        try:
            table['node'].reset_default()
        except:
            pass
    
    # The order is important. We do want to clear from the top, i.e.
    # delete objects that use other objects, e.g. table entries use
    # selector groups and selector groups use action profile members
    

    # Clear Match Tables
    for table in p4.info(return_info=True, print_info=False):
        if table['type'] in ['MATCH_DIRECT', 'MATCH_INDIRECT_SELECTOR']:
            _clear(table, verbose=verbose, batching=batching)

    # Clear Selectors
    for table in p4.info(return_info=True, print_info=False):
        if table['type'] in ['SELECTOR']:
            _clear(table, verbose=verbose, batching=batching)
            
    # Clear Action Profiles
    for table in p4.info(return_info=True, print_info=False):
        if table['type'] in ['ACTION_PROFILE']:
            _clear(table, verbose=verbose, batching=batching)
    
clear_all()


# map the 3 configured buckets to the two servers with a 2:1 ratio
get_server_from_bucket = p4.Ingress.get_server_from_bucket
get_server_from_bucket.add_with_fwd_to_server(bucket_id=0, egress_port=52, dip=ip_address("192.168.63.16"), dmac=0xb883036f4311)
get_server_from_bucket.add_with_fwd_to_server(bucket_id=1, egress_port=52, dip=ip_address("192.168.63.16"), dmac=0xb883036f4311)
get_server_from_bucket.add_with_fwd_to_server(bucket_id=2, egress_port=52, dip=ip_address("192.168.63.16"), dmac=0xb883036f4311)
# update port id and mac
get_server_from_bucket.add_with_fwd_to_server(bucket_id=3, egress_port=20, dip=ip_address("192.168.63.19"), dmac=0xb883036f43d1) 

# map the server IDs to their IP, port, and MAC address
get_server_from_id = p4.Ingress.get_server_from_id
get_server_from_id.add_with_fwd_to_server(server_id=1, egress_port=52, dip=ip_address("192.168.63.16"), dmac=0xb883036f4311)
# update port id and mac
get_server_from_id.add_with_fwd_to_server(server_id=2, egress_port=20, dip=ip_address("192.168.63.19"), dmac=0xb883036f43d1)

# initialize the registers
bucket_counter_reg = p4.Ingress.bucket_counter_reg
bucket_counter_reg.mod(register_index=0, f1=0)

'''counter_reg = p4.Ingress.counter_reg
counter_reg.mod(register_index=0, f1=0)

debug_reg = p4.Ingress.debug_reg
debug_2_reg = p4.Ingress.debug_2_reg
debug_3_reg = p4.Ingress.debug_3_reg

for x in range(0,5):
    debug_reg.mod(register_index=x, f1=0)
    debug_2_reg.mod(register_index=x, f1=0)
    debug_3_reg.mod(register_index=x, f1=0)'''

# clean the counters
def clear_counters(table_node):
    for e in table_node.get(regex=True):
        e.data[b'$COUNTER_SPEC_BYTES'] = 0
        e.data[b'$COUNTER_SPEC_PKTS'] = 0
        e.push()

# dump everything
get_server_from_bucket.dump(table=True)
get_server_from_id.dump(table=True)
bucket_counter_reg.dump(from_hw=1)
'''debug_reg.dump(from_hw=1)
debug_2_reg.dump(from_hw=1)'''
