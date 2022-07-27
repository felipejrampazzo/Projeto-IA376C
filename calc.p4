/* -*- P4_16 -*- */

#include <core.p4>
#include <v1model.p4>

#define DIMENSION 4

register<bit<32>>(20) register_pub_matrix;
register<bit<32>>(10) register_secret_vector;
register<bit<32>>(10) register_noise_vector;
register<bit<32>>(10) register_public_vector;
register<bit<32>>(36) register_public_vector_full;
register<bit<32>>(18) register_mod_public_vector;
register <bit<32>>(4) register_seed;


header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}


const bit<16> P4CALC_ETYPE = 0x1234;
const bit<8>  P4CALC_P     = 0x4B; // K - KYBER
const bit<8>  GEN  = 0x47;   // 'G'
const bit<8>  ENC = 0x45;   // 'E'
const bit<8>  DEC   = 0x44;   // 'D'
const bit<32> PARAM_Q = 3329;

header p4calc_t {
    bit<8>  p;
    bit<8>  op;

    bit<32> t_0;
    bit<32> t_1;
    bit<32> t_2;
    bit<32> t_3;
    bit<32> t_4;
    bit<32> t_5;
    bit<32> t_6;
    bit<32> t_7;
    bit<32> t_8;
    bit<32> t_9;
    
    bit<32> seed;
}


struct headers {
    ethernet_t   ethernet;
    p4calc_t     p4calc;
}


struct metadata {
    /* In our case it is empty */
}

/*************************************************************************
 ***********************  P A R S E R  ***********************************
 *************************************************************************/
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            P4CALC_ETYPE : check_p4calc;
            default      : accept;
        }
    }

    state check_p4calc {
        transition select(packet.lookahead<p4calc_t>().p) {
            (P4CALC_P) : parse_p4calc;
            default    : accept;
        }
    }

    state parse_p4calc {
        packet.extract(hdr.p4calc);
        transition accept;
    }
}

/*************************************************************************
 ************   C H E C K S U M    V E R I F I C A T I O N   *************
 *************************************************************************/
control MyVerifyChecksum(inout headers hdr,
                         inout metadata meta) {
    apply { }
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action send_back() {
        bit<48> tmp;
        
        tmp = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = tmp;

        /* Send the packet back to the port it came from */
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    #define gen_matrix(INDEX, ROUND) action gen_matrix_i##INDEX##_r##ROUND##() { \
        bit<32> coef;                                                            \
        register_seed.read(coef, 0);                                             \
        hash(coef, HashAlgorithm.crc32, (bit<32>) 0, {coef}, (bit<32>) PARAM_Q); \
        register_pub_matrix.write(##INDEX##, coef);                              \
        register_seed.write(0, coef);                                            \
    }
    gen_matrix(0, 1)
    gen_matrix(1, 1)
    gen_matrix(2, 1)
    gen_matrix(3, 1)
    gen_matrix(4, 1)
    gen_matrix(5, 1)
    gen_matrix(6, 1)
    gen_matrix(7, 1)
    gen_matrix(8, 1)
    gen_matrix(9, 1)
    gen_matrix(10, 1)
    gen_matrix(11, 1)
    gen_matrix(12, 1)
    gen_matrix(13, 1)
    gen_matrix(14, 1)
    gen_matrix(15, 1)
    gen_matrix(16, 1)
    gen_matrix(17, 1)
    gen_matrix(18, 1)
    gen_matrix(19, 1)
      

    #define gen_secret_vector(INDEX) action gen_secret_vector_i##INDEX##() { \
        bit<32> coef; \
        random(coef, 1, 4); \
        register_secret_vector.write(##INDEX##, coef); \
    }
    gen_secret_vector(0)
    gen_secret_vector(1)
    gen_secret_vector(2)
    gen_secret_vector(3)
    gen_secret_vector(4)
    gen_secret_vector(5)
    gen_secret_vector(6)
    gen_secret_vector(7)
    gen_secret_vector(8)
    gen_secret_vector(9)


    #define gen_noise_vector(INDEX) action gen_noise_vector_i##INDEX##() { \
        bit<32> coef; \
        random(coef, 1, 4); \
        register_noise_vector.write(##INDEX##, coef); \
    }
    gen_noise_vector(0)
    gen_noise_vector(1)
    gen_noise_vector(2)
    gen_noise_vector(3)
    gen_noise_vector(4)
    gen_noise_vector(5)
    gen_noise_vector(6)
    gen_noise_vector(7)
    gen_noise_vector(8)
    gen_noise_vector(9)


    #define matrix_mult(I_A, I_SU, I_TU) action matrix_mult_ia##I_A##_isr##I_SU##_itu##I_TU##() { \
        bit<32> a;  \
        bit<32> s_r;  \
        bit<32> t_u;  \
        bit<32> temp;  \
        register_pub_matrix.read(a, ##I_A##);  \
        register_secret_vector.read(s_r, ##I_SU##);  \
        register_public_vector_full.read(t_u, ##I_TU##);  \
        temp = (a * s_r) + t_u;  \
        register_public_vector_full.write(##I_TU##, temp);  \
    }
    matrix_mult(0, 0, 0)
    matrix_mult(0, 1, 1)
    matrix_mult(0, 2, 2)
    matrix_mult(0, 3, 3)
    matrix_mult(0, 4, 4)
    matrix_mult(1, 0, 1)
    matrix_mult(1, 1, 2)
    matrix_mult(1, 2, 3)
    matrix_mult(1, 3, 4)
    matrix_mult(1, 4, 5)
    matrix_mult(2, 0, 2)
    matrix_mult(2, 1, 3)
    matrix_mult(2, 2, 4)
    matrix_mult(2, 3, 5)
    matrix_mult(2, 4, 6)
    matrix_mult(3, 0, 3)
    matrix_mult(3, 1, 4)
    matrix_mult(3, 2, 5)
    matrix_mult(3, 3, 6)
    matrix_mult(3, 4, 7)
    matrix_mult(4, 0, 4)
    matrix_mult(4, 1, 5)
    matrix_mult(4, 2, 6)
    matrix_mult(4, 3, 7)
    matrix_mult(4, 4, 8)
    matrix_mult(5, 5, 9)
    matrix_mult(5, 6, 10)
    matrix_mult(5, 7, 11)
    matrix_mult(5, 8, 12)
    matrix_mult(5, 9, 13)
    matrix_mult(6, 5, 10)
    matrix_mult(6, 6, 11)
    matrix_mult(6, 7, 12)
    matrix_mult(6, 8, 13)
    matrix_mult(6, 9, 14)
    matrix_mult(7, 5, 11)
    matrix_mult(7, 6, 12)
    matrix_mult(7, 7, 13)
    matrix_mult(7, 8, 14)
    matrix_mult(7, 9, 15)
    matrix_mult(8, 5, 12)
    matrix_mult(8, 6, 13)
    matrix_mult(8, 7, 14)
    matrix_mult(8, 8, 15)
    matrix_mult(8, 9, 16)
    matrix_mult(9, 5, 13)
    matrix_mult(9, 6, 14)
    matrix_mult(9, 7, 15)
    matrix_mult(9, 8, 16)
    matrix_mult(9, 9, 17)
    matrix_mult(10, 0, 18)
    matrix_mult(10, 1, 19)
    matrix_mult(10, 2, 20)
    matrix_mult(10, 3, 21)
    matrix_mult(10, 4, 22)
    matrix_mult(11, 0, 19)
    matrix_mult(11, 1, 20)
    matrix_mult(11, 2, 21)
    matrix_mult(11, 3, 22)
    matrix_mult(11, 4, 23)
    matrix_mult(12, 0, 20)
    matrix_mult(12, 1, 21)
    matrix_mult(12, 2, 22)
    matrix_mult(12, 3, 23)
    matrix_mult(12, 4, 24)
    matrix_mult(13, 0, 21)
    matrix_mult(13, 1, 22)
    matrix_mult(13, 2, 23)
    matrix_mult(13, 3, 24)
    matrix_mult(13, 4, 25)
    matrix_mult(14, 0, 22)
    matrix_mult(14, 1, 23)
    matrix_mult(14, 2, 24)
    matrix_mult(14, 3, 25)
    matrix_mult(14, 4, 26)
    matrix_mult(15, 5, 27)
    matrix_mult(15, 6, 28)
    matrix_mult(15, 7, 29)
    matrix_mult(15, 8, 30)
    matrix_mult(15, 9, 31)
    matrix_mult(16, 5, 28)
    matrix_mult(16, 6, 29)
    matrix_mult(16, 7, 30)
    matrix_mult(16, 8, 31)
    matrix_mult(16, 9, 32)
    matrix_mult(17, 5, 29)
    matrix_mult(17, 6, 30)
    matrix_mult(17, 7, 31)
    matrix_mult(17, 8, 32)
    matrix_mult(17, 9, 33)
    matrix_mult(18, 5, 30)
    matrix_mult(18, 6, 31)
    matrix_mult(18, 7, 32)
    matrix_mult(18, 8, 33)
    matrix_mult(18, 9, 34)
    matrix_mult(19, 5, 31)
    matrix_mult(19, 6, 32)
    matrix_mult(19, 7, 33)
    matrix_mult(19, 8, 34)
    matrix_mult(19, 9, 35)


    #define poly_pub_add(X, Y, Z) action poly_pub_add_##X##_##Y##_##Z##() { \
        bit<32> x; \
        bit<32> y; \
        bit<32> sum; \
        register_public_vector_full.read(x, ##X##);  \
        register_public_vector_full.read(y, ##Y##); \
        sum = x + y; \
        register_mod_public_vector.write(##Z##, sum); \
    }
    poly_pub_add(0, 9, 0)
    poly_pub_add(1, 10, 1)
    poly_pub_add(2, 11, 2)
    poly_pub_add(3, 12, 3)
    poly_pub_add(4, 13, 4)
    poly_pub_add(5, 14, 5)
    poly_pub_add(6, 15, 6)
    poly_pub_add(7, 16, 7)
    poly_pub_add(8, 17, 8)
    poly_pub_add(18, 27, 9)
    poly_pub_add(19, 28, 10)
    poly_pub_add(20, 29, 11)
    poly_pub_add(21, 30, 12)
    poly_pub_add(22, 31, 13)
    poly_pub_add(23, 32, 14)
    poly_pub_add(24, 33, 15)
    poly_pub_add(25, 34, 16)
    poly_pub_add(26, 35, 17)

    #define poly_mod(X, Y, Z) action poly_mod_##X##_##Y##_##Z##() { \
        bit<32> x; \
        bit<32> y; \
        bit<32> e;  \
        bit<32> minus; \
        register_mod_public_vector.read(x, ##X##);  \
        if (##Y## == 100){ \
            y = 0; \
        } \
        else{ \
            register_mod_public_vector.read(y, ##Y##); \
        } \
        hash(x, HashAlgorithm.identity, (bit<32>) 0, {x}, (bit<32>) PARAM_Q); \
        hash(y, HashAlgorithm.identity, (bit<32>) 0, {y}, (bit<32>) PARAM_Q); \
        if (x < y){ \
            x = x + PARAM_Q; \
        } \
        minus = x - y; \
        register_noise_vector.read(e, ##Z##); \
        minus = minus + e; \
        hash(minus, HashAlgorithm.identity, (bit<32>) 0, {minus}, (bit<32>) PARAM_Q); \
        register_public_vector.write(##Z##, minus); \
        hdr.p4calc.t_##Z## = minus; \
    }
    poly_mod(4, 100, 0)
    poly_mod(5, 0, 1)
    poly_mod(6, 1, 2)
    poly_mod(7, 2, 3)
    poly_mod(8, 3, 4)
    poly_mod(13, 100, 5)
    poly_mod(14, 9, 6)
    poly_mod(15, 10, 7)
    poly_mod(16, 11, 8)
    poly_mod(17, 12, 9)


    action gen_keys() {
        register_seed.write(0, hdr.p4calc.seed);
        gen_matrix_i0_r1();
        gen_matrix_i1_r1();
        gen_matrix_i2_r1();
        gen_matrix_i3_r1();
        gen_matrix_i4_r1();
        gen_matrix_i5_r1();
        gen_matrix_i6_r1();
        gen_matrix_i7_r1();
        gen_matrix_i8_r1();
        gen_matrix_i9_r1();
        gen_matrix_i10_r1();
        gen_matrix_i11_r1();
        gen_matrix_i12_r1();
        gen_matrix_i13_r1();
        gen_matrix_i14_r1();
        gen_matrix_i15_r1();
        gen_matrix_i16_r1();
        gen_matrix_i17_r1();
        gen_matrix_i18_r1();
        gen_matrix_i19_r1();

        gen_secret_vector_i0();
        gen_secret_vector_i1();
        gen_secret_vector_i2();
        gen_secret_vector_i3();
        gen_secret_vector_i4();
        gen_secret_vector_i5();
        gen_secret_vector_i6();
        gen_secret_vector_i7();
        gen_secret_vector_i8();
        gen_secret_vector_i9();

        gen_noise_vector_i0();
        gen_noise_vector_i1();
        gen_noise_vector_i2();
        gen_noise_vector_i3();
        gen_noise_vector_i4();
        gen_noise_vector_i5();
        gen_noise_vector_i6();
        gen_noise_vector_i7();
        gen_noise_vector_i8();
        gen_noise_vector_i9();

        matrix_mult_ia0_isr0_itu0();
        matrix_mult_ia0_isr1_itu1();
        matrix_mult_ia0_isr2_itu2();
        matrix_mult_ia0_isr3_itu3();
        matrix_mult_ia0_isr4_itu4();
        matrix_mult_ia1_isr0_itu1();
        matrix_mult_ia1_isr1_itu2();
        matrix_mult_ia1_isr2_itu3();
        matrix_mult_ia1_isr3_itu4();
        matrix_mult_ia1_isr4_itu5();
        matrix_mult_ia2_isr0_itu2();
        matrix_mult_ia2_isr1_itu3();
        matrix_mult_ia2_isr2_itu4();
        matrix_mult_ia2_isr3_itu5();
        matrix_mult_ia2_isr4_itu6();
        matrix_mult_ia3_isr0_itu3();
        matrix_mult_ia3_isr1_itu4();
        matrix_mult_ia3_isr2_itu5();
        matrix_mult_ia3_isr3_itu6();
        matrix_mult_ia3_isr4_itu7();
        matrix_mult_ia4_isr0_itu4();
        matrix_mult_ia4_isr1_itu5();
        matrix_mult_ia4_isr2_itu6();
        matrix_mult_ia4_isr3_itu7();
        matrix_mult_ia4_isr4_itu8();

        matrix_mult_ia5_isr5_itu9();
        matrix_mult_ia5_isr6_itu10();
        matrix_mult_ia5_isr7_itu11();
        matrix_mult_ia5_isr8_itu12();
        matrix_mult_ia5_isr9_itu13();
        matrix_mult_ia6_isr5_itu10();
        matrix_mult_ia6_isr6_itu11();
        matrix_mult_ia6_isr7_itu12();
        matrix_mult_ia6_isr8_itu13();
        matrix_mult_ia6_isr9_itu14();
        matrix_mult_ia7_isr5_itu11();
        matrix_mult_ia7_isr6_itu12();
        matrix_mult_ia7_isr7_itu13();
        matrix_mult_ia7_isr8_itu14();
        matrix_mult_ia7_isr9_itu15();
        matrix_mult_ia8_isr5_itu12();
        matrix_mult_ia8_isr6_itu13();
        matrix_mult_ia8_isr7_itu14();
        matrix_mult_ia8_isr8_itu15();
        matrix_mult_ia8_isr9_itu16();
        matrix_mult_ia9_isr5_itu13();
        matrix_mult_ia9_isr6_itu14();
        matrix_mult_ia9_isr7_itu15();
        matrix_mult_ia9_isr8_itu16();
        matrix_mult_ia9_isr9_itu17();

        matrix_mult_ia10_isr0_itu18();
        matrix_mult_ia10_isr1_itu19();
        matrix_mult_ia10_isr2_itu20();
        matrix_mult_ia10_isr3_itu21();
        matrix_mult_ia10_isr4_itu22();
        matrix_mult_ia11_isr0_itu19();
        matrix_mult_ia11_isr1_itu20();
        matrix_mult_ia11_isr2_itu21();
        matrix_mult_ia11_isr3_itu22();
        matrix_mult_ia11_isr4_itu23();
        matrix_mult_ia12_isr0_itu20();
        matrix_mult_ia12_isr1_itu21();
        matrix_mult_ia12_isr2_itu22();
        matrix_mult_ia12_isr3_itu23();
        matrix_mult_ia12_isr4_itu24();
        matrix_mult_ia13_isr0_itu21();
        matrix_mult_ia13_isr1_itu22();
        matrix_mult_ia13_isr2_itu23();
        matrix_mult_ia13_isr3_itu24();
        matrix_mult_ia13_isr4_itu25();
        matrix_mult_ia14_isr0_itu22();
        matrix_mult_ia14_isr1_itu23();
        matrix_mult_ia14_isr2_itu24();
        matrix_mult_ia14_isr3_itu25();
        matrix_mult_ia14_isr4_itu26();

        matrix_mult_ia15_isr5_itu27();
        matrix_mult_ia15_isr6_itu28();
        matrix_mult_ia15_isr7_itu29();
        matrix_mult_ia15_isr8_itu30();
        matrix_mult_ia15_isr9_itu31();
        matrix_mult_ia16_isr5_itu28();
        matrix_mult_ia16_isr6_itu29();
        matrix_mult_ia16_isr7_itu30();
        matrix_mult_ia16_isr8_itu31();
        matrix_mult_ia16_isr9_itu32();
        matrix_mult_ia17_isr5_itu29();
        matrix_mult_ia17_isr6_itu30();
        matrix_mult_ia17_isr7_itu31();
        matrix_mult_ia17_isr8_itu32();
        matrix_mult_ia17_isr9_itu33();
        matrix_mult_ia18_isr5_itu30();
        matrix_mult_ia18_isr6_itu31();
        matrix_mult_ia18_isr7_itu32();
        matrix_mult_ia18_isr8_itu33();
        matrix_mult_ia18_isr9_itu34();
        matrix_mult_ia19_isr5_itu31();
        matrix_mult_ia19_isr6_itu32();
        matrix_mult_ia19_isr7_itu33();
        matrix_mult_ia19_isr8_itu34();
        matrix_mult_ia19_isr9_itu35();

        poly_pub_add_0_9_0();
        poly_pub_add_1_10_1();
        poly_pub_add_2_11_2();
        poly_pub_add_3_12_3();
        poly_pub_add_4_13_4();
        poly_pub_add_5_14_5();
        poly_pub_add_6_15_6();
        poly_pub_add_7_16_7();
        poly_pub_add_8_17_8();

        poly_pub_add_18_27_9();
        poly_pub_add_19_28_10();
        poly_pub_add_20_29_11();
        poly_pub_add_21_30_12();
        poly_pub_add_22_31_13();
        poly_pub_add_23_32_14();
        poly_pub_add_24_33_15();
        poly_pub_add_25_34_16();
        poly_pub_add_26_35_17();

        poly_mod_4_100_0();
        poly_mod_5_0_1();
        poly_mod_6_1_2();
        poly_mod_7_2_3();
        poly_mod_8_3_4();
        poly_mod_13_100_5();
        poly_mod_14_9_6();
        poly_mod_15_10_7();
        poly_mod_16_11_8();
        poly_mod_17_12_9();

        send_back();
    }

    action enc() {
        // gen_secret_vector(); // r
        // gen_noise_vector(); // e1
        bit<32> e2;
        random(e2, 0, 4);
        bit<32> m;
        random(m, 0, 2);

        send_back();
    }

    action dec() {

        send_back();
    }

    action operation_drop() {
        mark_to_drop(standard_metadata);
    }

    table calculate {
        key = {
            hdr.p4calc.op  : exact;
        }
        actions = {
            gen_keys;
            enc;
            dec;
            operation_drop;
        }
        const default_action = operation_drop();
        const entries = {
            GEN : gen_keys();
            ENC: enc();
            DEC  : dec();
        }
    }


    apply {
        if (hdr.p4calc.isValid()) {
            calculate.apply();
        } else {
            operation_drop();
        }
    }
}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

/*************************************************************************
 *************   C H E C K S U M    C O M P U T A T I O N   **************
 *************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
 ***********************  D E P A R S E R  *******************************
 *************************************************************************/
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.p4calc);
    }
}

/*************************************************************************
 ***********************  S W I T T C H **********************************
 *************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
