/*
 * (C) 2007-22 - ntop.org and contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>
 *
 */


#include <inttypes.h>  // for PRIx64, PRIi32
#include <stdint.h>    // for uint8_t
#include <stdio.h>     // for printf, fprintf, size_t, stderr, stdout
#include <string.h>    // for memset, strcpy, strncpy
#include "hexdump.h"   // for fhexdump
#include "n2n.h"       // for n2n_common_t, n2n_REGISTER_SUPER_t, n2n_REGIST...
#include "n2n_wire.h"  // for encode_REGISTER, encode_REGISTER_SUPER, encode...


void init_ip_subnet (n2n_ip_subnet_t * d) {
    d->net_addr = 0x20212223;
    d->net_bitlen = 25;
}

void print_ip_subnet (char *test_name, char *field, n2n_ip_subnet_t * d) {
    printf("%s: %s.net_addr = 0x%08x\n",
           test_name, field, d->net_addr);
    printf("%s: %s.net_bitlen = %i\n",
           test_name, field, d->net_bitlen);
}

void init_mac (n2n_mac_t mac, const uint8_t o0, const uint8_t o1,
               const uint8_t o2, const uint8_t o3,
               const uint8_t o4, const uint8_t o5) {
    mac[0] = o0;
    mac[1] = o1;
    mac[2] = o2;
    mac[3] = o3;
    mac[4] = o4;
    mac[5] = o5;
}

void print_mac (char *test_name, char *field, n2n_mac_t mac) {
    printf("%s: %s[] = %x:%x:%x:%x:%x:%x\n",
           test_name, field,
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void init_auth (n2n_auth_t *auth) {
    auth->scheme = n2n_auth_simple_id;
    auth->token_size = 16;
    auth->token[0] = 0xfe;
    auth->token[4] = 0xfd;
    auth->token[8] = 0xfc;
    auth->token[15] = 0xfb;
}

void print_auth (char *test_name, char *field, n2n_auth_t *auth) {
    printf("%s: %s.scheme = %i\n", test_name, field, auth->scheme);
    printf("%s: %s.token_size = %i\n", test_name, field, auth->token_size);
    printf("%s: %s.token[0] = 0x%02x\n", test_name, field, auth->token[0]);
}

void init_common (n2n_common_t *common, char *community) {
    memset( common, 0, sizeof(*common) );
    common->ttl = N2N_DEFAULT_TTL;
    common->flags = 0;
    strncpy( (char *)common->community, community, N2N_COMMUNITY_SIZE);
    common->community[N2N_COMMUNITY_SIZE - 1] = '\0';
}

void print_common (char *test_name, n2n_common_t *common) {
    printf("%s: common.ttl = %i\n", test_name, common->ttl);
    printf("%s: common.flags = %i\n", test_name, common->flags);
    printf("%s: common.community = \"%s\"\n", test_name, common->community);
}

void test_REGISTER (n2n_common_t *common) {
    char *test_name = "REGISTER";

    common->pc = n2n_register;
    printf("%s: common.pc = %i\n", test_name, common->pc);

    n2n_REGISTER_t reg;
    memset( &reg, 0, sizeof(reg) );
    init_mac( reg.srcMac, 0,1,2,3,4,5);
    init_mac( reg.dstMac, 0x10,0x11,0x12,0x13,0x14,0x15);
    init_ip_subnet(&reg.dev_addr);
    strcpy( (char *)reg.dev_desc, "Dummy_Dev_Desc" );

    printf("%s: reg.cookie = %i\n", test_name, reg.cookie);
    print_mac(test_name, "reg.srcMac", reg.srcMac);
    print_mac(test_name, "reg.dstMac", reg.dstMac);
    // TODO: print reg.sock
    print_ip_subnet(test_name, "reg.dev_addr", &reg.dev_addr);
    printf("%s: reg.dev_desc = \"%s\"\n", test_name, reg.dev_desc);
    printf("\n");

    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t idx = 0;
    size_t retval = encode_REGISTER( pktbuf, &idx, common, &reg);

    printf("%s: output retval = 0x%" PRIx64 "\n", test_name, retval);
    printf("%s: output idx = 0x%" PRIx64 "\n", test_name, idx);
    fhexdump(0, pktbuf, idx, stdout);

    // TODO: decode_REGISTER() and print

    fprintf(stderr, "%s: tested\n", test_name);
    printf("\n");
}

void test_REGISTER_SUPER (n2n_common_t *common) {
    char *test_name = "REGISTER_SUPER";

    common->pc = n2n_register_super;
    printf("%s: common.pc = %i\n", test_name, common->pc);

    n2n_REGISTER_SUPER_t reg;
    memset( &reg, 0, sizeof(reg) );
    init_mac( reg.edgeMac, 0x20,0x21,0x22,0x23,0x24,0x25);
    // n2n_sock_t sock
    init_ip_subnet(&reg.dev_addr);
    strcpy( (char *)reg.dev_desc, "Dummy_Dev_Desc" );
    init_auth(&reg.auth);
    reg.key_time = 600;


    printf("%s: reg.cookie = %i\n", test_name, reg.cookie);
    print_mac(test_name, "reg.edgeMac", reg.edgeMac);
    // TODO: print reg.sock
    print_ip_subnet(test_name, "reg.dev_addr", &reg.dev_addr);
    printf("%s: reg.dev_desc = \"%s\"\n", test_name, reg.dev_desc);
    print_auth(test_name, "reg.auth", &reg.auth);
    printf("%s: reg.key_time = %" PRIi32 "\n", test_name, reg.key_time);
    printf("\n");

    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t idx = 0;
    size_t retval = encode_REGISTER_SUPER( pktbuf, &idx, common, &reg);

    printf("%s: output retval = 0x%" PRIx64 "\n", test_name, retval);
    printf("%s: output idx = 0x%" PRIx64 "\n", test_name, idx);
    fhexdump(0, pktbuf, idx, stdout);

    // TODO: decode_REGISTER_SUPER() and print

    fprintf(stderr, "%s: tested\n", test_name);
    printf("\n");
}

void test_UNREGISTER_SUPER (n2n_common_t *common) {
    char *test_name = "UNREGISTER_SUPER";

    common->pc = n2n_unregister_super;
    printf("%s: common.pc = %i\n", test_name, common->pc);

    n2n_UNREGISTER_SUPER_t unreg;
    memset( &unreg, 0, sizeof(unreg) );
    init_auth(&unreg.auth);
    init_mac( unreg.srcMac, 0x30,0x31,0x32,0x33,0x34,0x35);


    print_auth(test_name, "unreg.auth", &unreg.auth);
    print_mac(test_name, "unreg.srcMac", unreg.srcMac);
    printf("\n");

    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t idx = 0;
    size_t retval = encode_UNREGISTER_SUPER( pktbuf, &idx, common, &unreg);

    printf("%s: output retval = 0x%" PRIx64 "\n", test_name, retval);
    printf("%s: output idx = 0x%" PRIx64 "\n", test_name, idx);
    fhexdump(0, pktbuf, idx, stdout);

    // TODO: decode_UNREGISTER_SUPER() and print

    fprintf(stderr, "%s: tested\n", test_name);
    printf("\n");
}

/* Unlike the tests above (which only encode + hexdump for manual eyeballing),
 * this one actually decodes what it encoded and asserts every field
 * round-trips -- covering both the "advertise" and "withdraw" branches, and
 * both a real /64 and the ::/0 default-route encoding, since those are the
 * two cases edge_utils.c's learn/cache logic and n2n.init's future
 * consumer both need to tell apart. Returns 0 on success, exits nonzero on
 * any mismatch so this can gate a build. */
int test_COMMUNITY_ROUTE_ADV (n2n_common_t *common) {
    char *test_name = "COMMUNITY_ROUTE_ADV";
    int failed = 0;

    struct {
        n2n_mac_t   mac;
        uint8_t     subnet[IPV6_SIZE];
        uint8_t     bitlen;
        uint8_t     withdraw;
    } cases[] = {
        { {0x40,0x41,0x42,0x43,0x44,0x45},
          {0xfd,0x00,0x00,0x03,0,0,0,0,0,0,0,0,0,0,0,0}, 64, 0 }, /* advertise fd00:3::/64 */
        { {0x40,0x41,0x42,0x43,0x44,0x45},
          {0xfd,0x00,0x00,0x03,0,0,0,0,0,0,0,0,0,0,0,0}, 64, 1 }, /* withdraw the same route */
        { {0x50,0x51,0x52,0x53,0x54,0x55},
          {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, 0, 0 },              /* advertise ::/0 (exit-node egress) */
    };
    size_t i;

    common->pc = MSG_TYPE_COMMUNITY_ROUTE_ADV;

    for(i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        n2n_COMMUNITY_ROUTE_ADV_t adv_in, adv_out;
        uint8_t pktbuf[N2N_PKT_BUF_SIZE];
        size_t idx = 0, rem;
        n2n_common_t common_out;

        memset(&adv_in, 0, sizeof(adv_in));
        memcpy(adv_in.srcMac, cases[i].mac, N2N_MAC_SIZE);
        memcpy(adv_in.subnet.net_addr, cases[i].subnet, IPV6_SIZE);
        adv_in.subnet.net_bitlen = cases[i].bitlen;
        adv_in.withdraw = cases[i].withdraw;

        encode_COMMUNITY_ROUTE_ADV(pktbuf, &idx, common, &adv_in);

        /* decode exactly like the real dispatchers do: decode_common() first
         * (it advances idx/rem past the header), then the message body. */
        rem = idx;
        idx = 0;
        decode_common(&common_out, pktbuf, &rem, &idx);
        decode_COMMUNITY_ROUTE_ADV(&adv_out, &common_out, pktbuf, &rem, &idx);

        if(memcmp(adv_in.srcMac, adv_out.srcMac, N2N_MAC_SIZE) != 0) {
            fprintf(stderr, "%s: case %zu: srcMac mismatch\n", test_name, i);
            failed = 1;
        }
        if(memcmp(adv_in.subnet.net_addr, adv_out.subnet.net_addr, IPV6_SIZE) != 0) {
            fprintf(stderr, "%s: case %zu: subnet.net_addr mismatch\n", test_name, i);
            failed = 1;
        }
        if(adv_in.subnet.net_bitlen != adv_out.subnet.net_bitlen) {
            fprintf(stderr, "%s: case %zu: subnet.net_bitlen mismatch (%u != %u)\n",
                    test_name, i, adv_in.subnet.net_bitlen, adv_out.subnet.net_bitlen);
            failed = 1;
        }
        if(adv_in.withdraw != adv_out.withdraw) {
            fprintf(stderr, "%s: case %zu: withdraw mismatch (%u != %u)\n",
                    test_name, i, adv_in.withdraw, adv_out.withdraw);
            failed = 1;
        }
        if(common_out.pc != MSG_TYPE_COMMUNITY_ROUTE_ADV) {
            fprintf(stderr, "%s: case %zu: common.pc mismatch after decode_common (%u != %u)\n",
                    test_name, i, common_out.pc, MSG_TYPE_COMMUNITY_ROUTE_ADV);
            failed = 1;
        }
    }

    if(!failed)
        fprintf(stderr, "%s: tested, %zu cases, all round-tripped correctly\n", test_name, sizeof(cases) / sizeof(cases[0]));

    return failed;
}

int main (int argc, char * argv[]) {
    char *test_name = "environment";
    int failed = 0;

    n2n_common_t common;
    init_common( &common, "abc123def456z" );
    print_common( test_name, &common );
    printf("\n");

    test_REGISTER(&common);
    test_REGISTER_SUPER(&common);
    test_UNREGISTER_SUPER(&common);
    failed |= test_COMMUNITY_ROUTE_ADV(&common);
    // TODO: add more wire tests

    return failed;
}

