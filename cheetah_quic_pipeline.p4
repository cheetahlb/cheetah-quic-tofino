/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/

const int BUCKET_SIZE = 6; // the size of the bucket, used to implement Weighted Round Robin

enum bit<16> ether_type_t {
    TPID = 0x8100,
    IPV4 = 0x0800,
    IPV6 = 0x86DD,
    ARP = 0x0806
}

typedef bit<48>   mac_addr_t;
typedef bit<32>   ipv4_addr_t;

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */

/* Standard ethernet header */
header ethernet_h {
    mac_addr_t    dst_addr;
    mac_addr_t    src_addr;
    ether_type_t  ether_type;
}

header ipv4_h {
    bit<4>       version;
    bit<4>       ihl;
    bit<8>       diffserv;
    bit<16>      total_len;
    bit<16>      identification;
    bit<3>       flags;
    bit<13>      frag_offset;
    bit<8>       ttl;
    bit<8>   	 protocol;
    bit<16>      hdr_checksum;
    ipv4_addr_t  src_addr;
    ipv4_addr_t  dst_addr;
}


header udpQuic_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length;
    bit<16> checksum;
    bit<1> hdr_type;
    bit<1> fixed;
    bit<2> pkt_type;
    bit<4> version;
}


header quicLong_h{
    bit<32> version;
    bit<8> dcid_length;
    bit<8> dcid_first_byte;
    bit<16> cookie;
    bit<40> dcid_residue;
    bit<8> scid_length;
    bit<64> src_cid;
}

header quicShort_h{
    bit<8> dcid_first_byte;
    bit<16> cookie;
    bit<40> dcid_residue;
}


/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
 
    /***********************  H E A D E R S  ************************/


struct my_ingress_headers_t {
    ethernet_h          ethernet;
    ipv4_h              ipv4;
    udpQuic_h           udpQuic;
    quicShort_h         quicShort;
    quicLong_h          quicLong;
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
    bit<16> bucket_id;   // the id of the bucket
    bit<16> server_id;   // the id of the server
    bit<16> udp_checksum; 
}

    /***********************  P A R S E R  **************************/
parser IngressParser(packet_in        pkt,
    /* User */    
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{

    Checksum() udp_ipv4_checksum;

    /* This is a mandatory state, required by Tofino Architecture */
     state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition meta_init;
    }

    /* User Metadata Initialization */
    state meta_init {
        //meta.l4_payload_checksum  = 0;
        meta.bucket_id = 0;
        meta.server_id=0;
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ether_type_t.IPV4 :  parse_ipv4;
            default :  accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        udp_ipv4_checksum.subtract({
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            });
        transition select(hdr.ipv4.protocol){
            17: parse_udpQuic;
            default: accept;
        }  
    }

    state parse_udpQuic {
        pkt.extract(hdr.udpQuic);
        udp_ipv4_checksum.subtract({
                hdr.udpQuic.src_port,
                hdr.udpQuic.dst_port,
                hdr.udpQuic.checksum
            });
        meta.udp_checksum = udp_ipv4_checksum.get();

        transition select(hdr.udpQuic.hdr_type){
            0: parse_quicShort;
            1: parse_quicLong;
            default: accept;
        }
    }

    state parse_quicShort {
        pkt.extract(hdr.quicShort);
        transition accept;
    }

    state parse_quicLong {
        pkt.extract(hdr.quicLong);
        transition accept;
    }

}

    /***************** M A T C H - A C T I O N  *********************/

// hash on both the client's IP address and UDP port
#define IPV4_HASH_FIELDS { \
    hdr.udpQuic.src_port,  \
    hdr.ipv4.src_addr  \
}

control calc_ipv4_hash(
    in my_ingress_headers_t   hdr,
    in my_ingress_metadata_t  meta,
    out bit<16>           sel_hash)
{
    Hash<bit<16>>(HashAlgorithm_t.CRC16) hash;

    apply {
        sel_hash = hash.get(IPV4_HASH_FIELDS);
    }
}

control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    /* The template type reflects the total width of the counter pair */
    bit<32> virtual_ip = 0xc0a84001; // 192.168.64.1
    bit<16> sel_hash;

    Register<bit<16>, bit<32>>(32w1) bucket_counter_reg;
    RegisterAction<bit<16>, bit<32>, bit<16>>(bucket_counter_reg) bucket_counter_reg_read = {
        void apply(inout bit<16> value, out bit<16> read_value){
            if(value >= BUCKET_SIZE - 1){
                value = 0;
            }
            else{
                value = value + 1;
            }
            read_value = value;
        }
    };

    action fwd_to_server(bit<9> egress_port, bit<32> dip, bit<48> dmac) {
        hdr.ipv4.dst_addr = dip;
        hdr.ethernet.dst_addr = dmac;
        ig_tm_md.ucast_egress_port = egress_port;
    }

    table get_server_from_id {
        key = {
            meta.server_id: exact;
        }
        actions = {
            fwd_to_server;
        }
        size=1024;
    }

    table get_server_from_bucket {
        key = {
            meta.bucket_id: exact;
        }
        actions = {
            fwd_to_server;
        }
        size = 1024;
    }

    apply {

        if(hdr.udpQuic.isValid()){
            // check if the packet is towards the VIP
            if(hdr.ipv4.dst_addr == virtual_ip){

                // check if it is an Initial QUIC packet with a long header
                if((hdr.udpQuic.hdr_type == 1) && (hdr.udpQuic.pkt_type == (bit<2>)0)){  

                    //  get the bucket counter to select the next server in the WRR    
                    meta.bucket_id = bucket_counter_reg_read.execute(0); 

                    // forward to the selected server
                    get_server_from_bucket.apply();
                }

                // any non-Initial packet
                else{

                    // compute the hash of the IP/UDP identifiers
                    calc_ipv4_hash.apply(hdr,meta,sel_hash);

                    // extract the cookie from a long or short header and XOR it with the hash of the IP/UDP identifiers
                    if (hdr.udpQuic.hdr_type == 1){
                        meta.server_id = sel_hash ^ hdr.quicLong.cookie;
                    }
                    else{
                        meta.server_id = sel_hash ^ hdr.quicShort.cookie;
                    }

                    // forward to the selected server
                    get_server_from_id.apply();
                }
            }

            //if the packet comes from a server (clients are attached on port 60)
            else if(ig_intr_md.ingress_port != 60){

                // replace the IP source with the VIP
                if(hdr.ipv4.isValid()){
                    hdr.ipv4.src_addr = virtual_ip;
                }

                // the client is connected to port '60'
                ig_tm_md.ucast_egress_port = 60;
            }

            // we disable the UDP checksum for simplicity
            // TODO: implement the UDP chekcsum update
            //if(hdr.udpQuic.isValid()){
            //    hdr.udpQuic.checksum = 0x0000;
            //}
        }
    }
}

    /*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{

    Checksum() ipv4_checksum;
    Checksum() udp_checksum;

    apply {
        if (hdr.ipv4.isValid()) {
            // update the checksum because of the VIP <-> DIP address modification
           hdr.ipv4.hdr_checksum = ipv4_checksum.update({
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            });
       }
       if(hdr.udpQuic.isValid()){
          hdr.udpQuic.checksum = udp_checksum.update({
                    hdr.ipv4.src_addr,
                    hdr.ipv4.dst_addr,
                    hdr.udpQuic.src_port,
                    hdr.udpQuic.dst_port,
                    meta.udp_checksum
                }); 
       }

        pkt.emit(hdr);
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
}

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */    
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    apply {
    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}


/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
