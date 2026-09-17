/**
 * (C) 2007-22 - ntop.org and contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */

#include "n2n.h"           // for n2n_edge_t, peer_info, getTraceLevel, N2N_...
// FIXME: if this headers is sorted alphabetically, the test_integration_edge
// fails with what looks like a struct rearrangement involving eee->stats

#include <errno.h>         // for errno
#include <stdbool.h>
#include <stdint.h>        // for uint32_t
#include <stdio.h>         // for snprintf, size_t, NULL
#include <string.h>        // for memcmp, memcpy, strerror, strncpy
#include <sys/types.h>     // for ssize_t
#include <time.h>          // for time, time_t
#include "config.h"        // for PACKAGE_VERSION
#include "management.h"    // for mgmt_req_t, send_reply, send_json_1str
#include "n2n_define.h"    // for N2N_PKT_BUF_SIZE, N2N_EVENT_DEBUG, N2N_EVE...
#include "n2n_typedefs.h"  // for n2n_edge_t, peer_info, n2n_edge_conf_t
#include "sn_selection.h"  // for sn_selection_criterion_str, selection_crit...
#include "strbuf.h"        // for strbuf_t, STRBUF_INIT
#include "uthash.h"        // for UT_hash_handle, HASH_ITER

#ifdef _WIN32
#include "win32/defs.h"
#else
#include <arpa/inet.h>     // for inet_ntoa
#include <netinet/in.h>    // for in_addr, htonl, in_addr_t
#include <sys/socket.h>    // for sendto, recvfrom, sockaddr_storage
#endif

size_t event_debug (strbuf_t *buf, char *tag, int data0, void *data1) {
    traceEvent(TRACE_DEBUG, "Unexpected call to event_debug");
    return 0;
}

size_t event_test (strbuf_t *buf, char *tag, int data0, void *data1) {
    size_t msg_len = gen_json_1str(buf, tag, "event", "test", (char *)data1);
    return msg_len;
}

size_t event_peer (strbuf_t *buf, char *tag, int data0, void *data1) {
    int action = data0;
    struct peer_info *peer = (struct peer_info *)data1;

    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;

    /*
     * Just the peer_info bits that are needed for lookup (maccaddr) or
     * firewall and routing (sockaddr)
     * If needed, other details can be fetched via the edges method call.
     */
    return snprintf(buf->str, buf->size,
                    "{"
                    "\"_tag\":\"%s\","
                    "\"_type\":\"event\","
                    "\"action\":%i,"
                    "\"macaddr\":\"%s\","
                    "\"sockaddr\":\"%s\"}\n",
                    tag,
                    action,
                    (is_null_mac(peer->mac_addr)) ? "" : macaddr_str(mac_buf, peer->mac_addr),
                    sock_to_cstr(sockbuf, &(peer->sock)));
}



static void mgmt_communities (mgmt_req_t *req, strbuf_t *buf) {

    if(req->eee->conf.header_encryption != HEADER_ENCRYPTION_NONE) {
        mgmt_error(req, buf, "noaccess");
        return;
    }

    send_json_1str(req, buf, "row", "community", (char *)req->eee->conf.community_name);
}

static void mgmt_supernodes (mgmt_req_t *req, strbuf_t *buf) {
    size_t msg_len;
    struct peer_info *peer, *tmpPeer;
    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;
    selection_criterion_str_t sel_buf;

    HASH_ITER(hh, req->eee->conf.supernodes, peer, tmpPeer) {

        /*
         * TODO:
         * The version string provided by the remote supernode could contain
         * chars that make our JSON invalid.
         * - do we care?
         */

        msg_len = snprintf(buf->str, buf->size,
                           "{"
                           "\"_tag\":\"%s\","
                           "\"_type\":\"row\","
                           "\"version\":\"%s\","
                           "\"purgeable\":%i,"
                           "\"current\":%i,"
                           "\"macaddr\":\"%s\","
                           "\"sockaddr\":\"%s\","
                           "\"selection\":\"%s\","
                           "\"last_seen\":%li,"
                           "\"uptime\":%li}\n",
                           req->tag,
                           peer->version,
                           peer->purgeable,
                           (peer == req->eee->curr_sn) ? (req->eee->sn_wait ? 2 : 1 ) : 0,
                           is_null_mac(peer->mac_addr) ? "" : macaddr_str(mac_buf, peer->mac_addr),
                           sock_to_cstr(sockbuf, &(peer->sock)),
                           sn_selection_criterion_str(req->eee, sel_buf, peer),
                           peer->last_seen,
                           peer->uptime);

        send_reply(req, buf, msg_len);
    }
}

/* Stage A IPv6 support: read-only view of eee->learned_routes, the IPv6
 * CIDRs other edges in the community have advertised via
 * MSG_TYPE_COMMUNITY_ROUTE_ADV (see that type's comment). This is the only
 * place this data leaves core -- nothing in n2n itself ever applies these
 * routes to the OS routing table; a platform integration layer (OpenWrt's
 * n2n.init today, a future Windows/Android/iOS client's own native code)
 * polls this command and decides what, if anything, to do with it. */
/* Look up a currently-known peer's dev_desc by MAC -- used to give the IPV6
 * ROUTES table a human-readable HINT column instead of a bare MAC, the same
 * kind of description the TAP table already shows for each peer. Checks
 * known_peers (p2p) then pending_peers (supernode-forwarded); NULL if this
 * MAC isn't a currently-known peer at all (e.g. the route only reached us
 * relayed through a supernode we're not directly peered with). */
static const char *find_peer_desc_by_mac (n2n_edge_t *eee, const n2n_mac_t mac) {
    /* dev_desc is uint8_t[], cast to char* for use as a plain C string below */
    struct peer_info *peer, *tmpPeer;

    HASH_ITER(hh, eee->known_peers, peer, tmpPeer) {
        if(memcmp(peer->mac_addr, mac, N2N_MAC_SIZE) == 0)
            return (const char *)peer->dev_desc;
    }
    HASH_ITER(hh, eee->pending_peers, peer, tmpPeer) {
        if(memcmp(peer->mac_addr, mac, N2N_MAC_SIZE) == 0)
            return (const char *)peer->dev_desc;
    }
    return NULL;
}

static void mgmt_routes (mgmt_req_t *req, strbuf_t *buf) {
    size_t msg_len;
    n2n_learned_route_t *route, *tmpRoute;
    macstr_t mac_buf;
    ip6str_t subnet_buf;
    const char *hint;

    HASH_ITER(hh, req->eee->learned_routes, route, tmpRoute) {

        inet_ntop(AF_INET6, route->subnet.net_addr, subnet_buf, sizeof(subnet_buf));
        hint = find_peer_desc_by_mac(req->eee, route->srcMac);

        msg_len = snprintf(buf->str, buf->size,
                           "{"
                           "\"_tag\":\"%s\","
                           "\"_type\":\"row\","
                           "\"macaddr\":\"%s\","
                           "\"subnet\":\"%s/%u\","
                           "\"hint\":\"%s\","
                           "\"last_seen\":%li}\n",
                           req->tag,
                           macaddr_str(mac_buf, route->srcMac),
                           subnet_buf,
                           route->subnet.net_bitlen,
                           hint ? hint : "",
                           route->last_seen);

        send_reply(req, buf, msg_len);
    }
}

static void mgmt_edges_row (mgmt_req_t *req, strbuf_t *buf, struct peer_info *peer, char *mode) {
    size_t msg_len;
    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;
    dec_ip_bit_str_t ip_bit_str = {'\0'};

    msg_len = snprintf(buf->str, buf->size,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"mode\":\"%s\","
                       "\"ip4addr\":\"%s\","
                       "\"purgeable\":%i,"
                       "\"local\":%i,"
                       "\"macaddr\":\"%s\","
                       "\"sockaddr\":\"%s\","
                       "\"desc\":\"%s\","
                       "\"last_p2p\":%li,\n"
                       "\"last_sent_query\":%li,\n"
                       "\"last_seen\":%li}\n",
                       req->tag,
                       mode,
                       (peer->dev_addr.net_addr == 0) ? "" : ip_subnet_to_str(ip_bit_str, &peer->dev_addr),
                       peer->purgeable,
                       peer->local,
                       (is_null_mac(peer->mac_addr)) ? "" : macaddr_str(mac_buf, peer->mac_addr),
                       sock_to_cstr(sockbuf, &(peer->sock)),
                       peer->dev_desc,
                       peer->last_p2p,
                       peer->last_sent_query,
                       peer->last_seen);

    send_reply(req, buf, msg_len);
}

static void mgmt_edges (mgmt_req_t *req, strbuf_t *buf) {
    struct peer_info *peer, *tmpPeer;

    // dump nodes with forwarding through supernodes
    HASH_ITER(hh, req->eee->pending_peers, peer, tmpPeer) {
        mgmt_edges_row(req, buf, peer, "pSp");
    }

    // dump peer-to-peer nodes
    HASH_ITER(hh, req->eee->known_peers, peer, tmpPeer) {
        mgmt_edges_row(req, buf, peer, "p2p");
    }
}

static void mgmt_edge_info (mgmt_req_t *req, strbuf_t *buf) {
    size_t msg_len;
    macstr_t mac_buf;
    struct in_addr ip_addr, ip_addr_mask;
    ipstr_t ip_address, ip_address_mask;
    n2n_sock_str_t sockbuf;

    ip_addr.s_addr = req->eee->device.ip_addr;
    inaddrtoa(ip_address, ip_addr);
    ip_addr_mask.s_addr = req->eee->device.device_mask;
    inaddrtoa(ip_address_mask, ip_addr_mask);

    msg_len = snprintf(buf->str, buf->size,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"version\":\"%s\","
                       "\"macaddr\":\"%s\","
                       "\"ip4addr\":\"%s\","
                       "\"ip4netmask\":\"%s\","
                       "\"sockaddr\":\"%s\"}\n",
                       req->tag,
                       PACKAGE_VERSION,
                       is_null_mac(req->eee->device.mac_addr) ? "" : macaddr_str(mac_buf, req->eee->device.mac_addr),
                       ip_address, ip_address_mask,
                       sock_to_cstr(sockbuf, &req->eee->conf.preferred_sock));

    send_reply(req, buf, msg_len);
}

static void mgmt_timestamps (mgmt_req_t *req, strbuf_t *buf) {
    size_t msg_len;

    msg_len = snprintf(buf->str, buf->size,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"start_time\":%lu,"
                       "\"last_super\":%ld,"
                       "\"last_p2p\":%ld}\n",
                       req->tag,
                       req->eee->start_time,
                       req->eee->last_sup,
                       req->eee->last_p2p);

    send_reply(req, buf, msg_len);
}

static void mgmt_packetstats (mgmt_req_t *req, strbuf_t *buf) {
    size_t msg_len;

    msg_len = snprintf(buf->str, buf->size,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"type\":\"transop\","
                       "\"tx_pkt\":%lu,"
                       "\"rx_pkt\":%lu}\n",
                       req->tag,
                       req->eee->transop.tx_cnt,
                       req->eee->transop.rx_cnt);

    send_reply(req, buf, msg_len);

    msg_len = snprintf(buf->str, buf->size,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"type\":\"p2p\","
                       "\"tx_pkt\":%u,"
                       "\"rx_pkt\":%u}\n",
                       req->tag,
                       req->eee->stats.tx_p2p,
                       req->eee->stats.rx_p2p);

    send_reply(req, buf, msg_len);

    msg_len = snprintf(buf->str, buf->size,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"type\":\"super\","
                       "\"tx_pkt\":%u,"
                       "\"rx_pkt\":%u}\n",
                       req->tag,
                       req->eee->stats.tx_sup,
                       req->eee->stats.rx_sup);

    send_reply(req, buf, msg_len);

    msg_len = snprintf(buf->str, buf->size,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"type\":\"super_broadcast\","
                       "\"tx_pkt\":%u,"
                       "\"rx_pkt\":%u}\n",
                       req->tag,
                       req->eee->stats.tx_sup_broadcast,
                       req->eee->stats.rx_sup_broadcast);

    send_reply(req, buf, msg_len);
}

static void mgmt_post_test (mgmt_req_t *req, strbuf_t *buf) {

    send_json_1str(req, buf, "row", "sending", "test");
    mgmt_event_post(N2N_EVENT_TEST, -1, req->argv);
}

// Forward define so we can include this in the mgmt_handlers[] table
static void mgmt_help (mgmt_req_t *req, strbuf_t *buf);
static void mgmt_help_events (mgmt_req_t *req, strbuf_t *buf);

static const mgmt_handler_t mgmt_handlers[] = {
    { .cmd = "reload_communities", .flags = FLAG_WROK, .help = "Reserved for supernode", .func = mgmt_unimplemented},

    { .cmd = "stop", .flags = FLAG_WROK, .help = "Gracefully exit edge", .func = mgmt_stop},
    { .cmd = "verbose", .flags = FLAG_WROK, .help = "Manage verbosity level", .func = mgmt_verbose},
    { .cmd = "communities", .help = "Show current community", .func = mgmt_communities},
    { .cmd = "edges", .help = "List current edges/peers", .func = mgmt_edges},
    { .cmd = "supernodes", .help = "List current supernodes", .func = mgmt_supernodes},
    { .cmd = "routes", .help = "List learned IPv6 community routes", .func = mgmt_routes},
    { .cmd = "info", .help = "Provide basic edge information", .func = mgmt_edge_info},
    { .cmd = "timestamps", .help = "Event timestamps", .func = mgmt_timestamps},
    { .cmd = "packetstats", .help = "traffic counters", .func = mgmt_packetstats},
    { .cmd = "post.test", .help = "send a test event", .func = mgmt_post_test},
    { .cmd = "help", .flags = FLAG_WROK, .help = "Show JSON commands", .func = mgmt_help},
    { .cmd = "help.events", .help = "Show available Subscribe topics", .func = mgmt_help_events},
};

/* Current subscriber for each event topic */
static mgmt_req_t mgmt_event_subscribers[] = {
    [N2N_EVENT_DEBUG] = { .eee = NULL, .type = N2N_MGMT_UNKNOWN, .tag = "\0" },
    [N2N_EVENT_TEST] = { .eee = NULL, .type = N2N_MGMT_UNKNOWN, .tag = "\0" },
    [N2N_EVENT_PEER] = { .eee = NULL, .type = N2N_MGMT_UNKNOWN, .tag = "\0" },
};

/* Map topic number to function */
// TODO: want this to be const
static mgmt_event_handler_t *mgmt_events[] = {
    [N2N_EVENT_DEBUG] = event_debug,
    [N2N_EVENT_TEST] = event_test,
    [N2N_EVENT_PEER] = event_peer,
};

/* Allow help and subscriptions to use topic name */
static const mgmt_events_t mgmt_event_names[] = {
    { .cmd = "debug", .topic = N2N_EVENT_DEBUG, .help = "All events - for event debugging"},
    { .cmd = "test", .topic = N2N_EVENT_TEST, .help = "Used only by post.test"},
    { .cmd = "peer", .topic = N2N_EVENT_PEER, .help = "Changes to peer list"},
};

void mgmt_event_post (enum n2n_event_topic topic, int data0, void *data1) {
    mgmt_req_t *debug = &mgmt_event_subscribers[N2N_EVENT_DEBUG];
    mgmt_req_t *sub = &mgmt_event_subscribers[topic];
    mgmt_event_handler_t *fn =  mgmt_events[topic];

    mgmt_event_post2(topic, data0, data1, debug, sub, fn);
}

static void mgmt_help_events (mgmt_req_t *req, strbuf_t *buf) {
    int i;
    int nr_handlers = sizeof(mgmt_event_names) / sizeof(mgmt_events_t);
    for( i=0; i < nr_handlers; i++ ) {
        int topic = mgmt_event_names[i].topic;
        mgmt_req_t *sub = &mgmt_event_subscribers[topic];

        mgmt_help_events_row(req, buf, sub, mgmt_event_names[i].cmd, mgmt_event_names[i].help);
    }
}

// TODO: want to keep the mgmt_handlers defintion const static, otherwise
// this whole function could be shared
static void mgmt_help (mgmt_req_t *req, strbuf_t *buf) {
    /*
     * Even though this command is readonly, we deliberately do not check
     * the type - allowing help replies to both read and write requests
     */

    int i;
    int nr_handlers = sizeof(mgmt_handlers) / sizeof(mgmt_handler_t);
    for( i=0; i < nr_handlers; i++ ) {
        mgmt_help_row(req, buf, mgmt_handlers[i].cmd, mgmt_handlers[i].help);
    }
}

static void handleMgmtJson (mgmt_req_t *req, char *udp_buf, const int recvlen) {

    strbuf_t *buf;
    char cmdlinebuf[80];

    /* save a copy of the commandline before we reuse the udp_buf */
    strncpy(cmdlinebuf, udp_buf, sizeof(cmdlinebuf)-1);
    cmdlinebuf[sizeof(cmdlinebuf)-1] = 0;

    traceEvent(TRACE_DEBUG, "mgmt json %s", cmdlinebuf);

    /* we reuse the buffer already on the stack for all our strings */
    STRBUF_INIT(buf, udp_buf, N2N_SN_PKTBUF_SIZE);

    if(!mgmt_req_init2(req, buf, (char *)&cmdlinebuf)) {
        // if anything failed during init
        return;
    }

    if(req->type == N2N_MGMT_SUB) {
        int handler;
        lookup_handler(handler, mgmt_event_names, req->argv0);
        if(handler == -1) {
            mgmt_error(req, buf, "unknowntopic");
            return;
        }

        int topic = mgmt_event_names[handler].topic;
        if(mgmt_event_subscribers[topic].type == N2N_MGMT_SUB) {
            send_json_1str(&mgmt_event_subscribers[topic], buf,
                           "unsubscribed", "topic", req->argv0);
            send_json_1str(req, buf, "replacing", "topic", req->argv0);
        }

        memcpy(&mgmt_event_subscribers[topic], req, sizeof(*req));

        send_json_1str(req, buf, "subscribe", "topic", req->argv0);
        return;
    }

    int handler;
    lookup_handler(handler, mgmt_handlers, req->argv0);
    if(handler == -1) {
        mgmt_error(req, buf, "unknowncmd");
        return;
    }

    if((req->type==N2N_MGMT_WRITE) && !(mgmt_handlers[handler].flags & FLAG_WROK)) {
        mgmt_error(req, buf, "readonly");
        return;
    }

    /*
     * TODO:
     * The tag provided by the requester could contain chars
     * that make our JSON invalid.
     * - do we care?
     */
    send_json_1str(req, buf, "begin", "cmd", req->argv0);

    mgmt_handlers[handler].func(req, buf);

    send_json_1str(req, buf, "end", "cmd", req->argv0);
    return;
}

/** Read a datagram from the management UDP socket and take appropriate
 *    action. */
void readFromMgmtSocket (n2n_edge_t *eee) {

    char udp_buf[N2N_PKT_BUF_SIZE]; /* Compete UDP packet */
    ssize_t recvlen;
    /* ssize_t sendlen; */
    mgmt_req_t req;
    size_t msg_len;
    time_t now;
    struct peer_info *peer, *tmpPeer;
    macstr_t mac_buf;
    char time_buf[10]; /* 9 digits + 1 terminating zero */
    char uptime_buf[20]; /* "YYYY/MM/DD HH:MM:SS" (19 chars) + 1 terminating zero -- only used for
                          * the SUPERNODES table, which shows this as an absolute calendar
                          * timestamp (when that specific supernode process started), not a
                          * duration -- see its computation below. */
    /* dec_ip_bit_str_t ip_bit_str = {'\0'}; */
    /* dec_ip_str_t ip_str = {'\0'}; */
    in_addr_t net;
    n2n_sock_str_t sockbuf;
    uint32_t num_pending_peers = 0;
    uint32_t num_known_peers = 0;
    uint32_t num = 0;
    selection_criterion_str_t sel_buf;

    req.sss = NULL;
    req.eee = eee;
    req.mgmt_sock = eee->udp_mgmt_sock;
    req.keep_running = eee->keep_running;
    req.mgmt_password_hash = eee->conf.mgmt_password_hash;
    req.sock_len = sizeof(req.sas);

    now = time(NULL);
    recvlen = recvfrom(eee->udp_mgmt_sock, udp_buf, N2N_PKT_BUF_SIZE, 0 /*flags*/,
                       &req.sender_sock, &req.sock_len);

    if(recvlen < 0) {
        traceEvent(TRACE_WARNING, "mgmt recvfrom failed: %d - %s", errno, strerror(errno));
        return; /* failed to receive data from UDP */
    }

    /* avoid parsing any uninitialized junk from the stack */
    udp_buf[recvlen] = 0;

    if((0 == memcmp(udp_buf, "help", 4)) || (0 == memcmp(udp_buf, "?", 1))) {
        strbuf_t *buf;
        STRBUF_INIT(buf, &udp_buf, sizeof(udp_buf));
        msg_len = snprintf(buf->str, buf->size,
                           "Help for edge management console:\n"
                           "\tstop    | Gracefully exit edge\n"
                           "\thelp    | This help message\n"
                           "\t+verb   | Increase verbosity of logging\n"
                           "\t-verb   | Decrease verbosity of logging\n"
                           "\tr ...   | start query with JSON reply\n"
                           "\tw ...   | start update with JSON reply\n"
                           "\ts ...   | subscribe to event channel JSON reply\n"
                           "\t<enter> | Display statistics\n\n");

        send_reply(&req, buf, msg_len);

        return;
    }

    if(0 == memcmp(udp_buf, "stop", 4)) {
        traceEvent(TRACE_NORMAL, "stop command received");
        *eee->keep_running = false;
        return;
    }

    if(0 == memcmp(udp_buf, "+verb", 5)) {
        setTraceLevel(getTraceLevel() + 1);

        traceEvent(TRACE_NORMAL, "+verb traceLevel=%u", (unsigned int) getTraceLevel());

        strbuf_t *buf;
        STRBUF_INIT(buf, &udp_buf, sizeof(udp_buf));
        msg_len = snprintf(buf->str, buf->size,
                           "> +OK traceLevel=%u\n", (unsigned int) getTraceLevel());

        send_reply(&req, buf, msg_len);

        return;
    }

    if(0 == memcmp(udp_buf, "-verb", 5)) {
        strbuf_t *buf;
        STRBUF_INIT(buf, &udp_buf, sizeof(udp_buf));

        if(getTraceLevel() > 0) {
            setTraceLevel(getTraceLevel() - 1);
            msg_len = snprintf(buf->str, buf->size,
                               "> -OK traceLevel=%u\n", getTraceLevel());
        } else {
            msg_len = snprintf(buf->str, buf->size,
                               "> -NOK traceLevel=%u\n", getTraceLevel());
        }

        traceEvent(TRACE_NORMAL, "-verb traceLevel=%u", (unsigned int) getTraceLevel());

        send_reply(&req, buf, msg_len);
        return;
    }

    if((udp_buf[0] >= 'a' && udp_buf[0] <= 'z') && (udp_buf[1] == ' ')) {
        /* this is a JSON request */
        handleMgmtJson(&req, udp_buf, recvlen);
        return;
    }

    traceEvent(TRACE_DEBUG, "mgmt status requested");

    msg_len = 0;
    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "COMMUNITY '%s'\n\n",
                        (eee->conf.header_encryption == HEADER_ENCRYPTION_NONE) ? (char*)eee->conf.community_name : "-- header encrypted --");
    /* Column widths chosen to line up with the SUPERNODES/IPV6 ROUTES tables
     * below -- all three now start their MAC column at the same offset (see
     * those tables' comments). Header built from the same format string as
     * the data rows, not hand-typed, so it can't drift out of alignment. */
    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        " ### | %-27s | %-17s | %-21s | %-15s | %9s | %10s\n",
                        "TAP", "MAC", "EDGE", "HINT", "LAST SEEN", "UPTIME");
    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "=========================================================================================================================\n");

    // dump nodes with forwarding through supernodes
    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "SUPERNODE FORWARD\n");
    num = 0;
    HASH_ITER(hh, eee->pending_peers, peer, tmpPeer) {
        ++num_pending_peers;
        net = htonl(peer->dev_addr.net_addr);
        snprintf(time_buf, sizeof(time_buf), "%8us", (unsigned int)(now - peer->last_seen));
        /* peer->sn_start_time: that *edge's* own start time, learned via a supernode's
         * proactive MSG_TYPE_REGISTER hint broadcast (sn_broadcast_edge_hints(), which
         * now fills in start_time the same way it already does dev_desc) -- n2n has no
         * edge-to-edge mechanism for this at all, so it's entirely dependent on the
         * supernode relaying it. 0 means never received one yet. Absolute-timestamp
         * display, not a duration -- see n2n_typedefs.h's sn_start_time comment for why
         * that matters (SUPERNODES table below hit real drift from doing it the other
         * way). */
        if(peer->sn_start_time)
            strftime(uptime_buf, sizeof(uptime_buf), "%Y/%m/%d %H:%M:%S", localtime(&peer->sn_start_time));
        msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                            "%4u | %-27s | %-17s | %-21s | %-15s | %9s | %10s\n",
                            ++num,
                            (peer->dev_addr.net_addr == 0) ? "" : inet_ntoa(*(struct in_addr *) &net),
                            (is_null_mac(peer->mac_addr)) ? "" : macaddr_str(mac_buf, peer->mac_addr),
                            sock_to_cstr(sockbuf, &(peer->sock)),
                            peer->dev_desc,
                            (peer->last_seen) ? time_buf : "",
                            peer->sn_start_time ? uptime_buf : "");

        sendto(eee->udp_mgmt_sock, udp_buf, msg_len, 0,
               &req.sender_sock, req.sock_len);
        msg_len = 0;
    }

    // dump peer-to-peer nodes
    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "-------------------------------------------------------------------------------------------------------------------------\n");
    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "PEER TO PEER\n");
    num = 0;
    HASH_ITER(hh, eee->known_peers, peer, tmpPeer) {
        ++num_known_peers;
        net = htonl(peer->dev_addr.net_addr);
        snprintf(time_buf, sizeof(time_buf), "%8us", (unsigned int)(now - peer->last_seen));
        /* see the matching comment in the SUPERNODE FORWARD block above */
        if(peer->sn_start_time)
            strftime(uptime_buf, sizeof(uptime_buf), "%Y/%m/%d %H:%M:%S", localtime(&peer->sn_start_time));
        msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                            "%4u | %-27s | %-17s | %-21s | %-15s | %9s | %10s\n",
                            ++num,
                            (peer->dev_addr.net_addr == 0) ? "" : inet_ntoa(*(struct in_addr *) &net),
                            (is_null_mac(peer->mac_addr)) ? "" : macaddr_str(mac_buf, peer->mac_addr),
                            sock_to_cstr(sockbuf, &(peer->sock)),
                            peer->dev_desc,
                            (peer->last_seen) ? time_buf : "",
                            peer->sn_start_time ? uptime_buf : "");

        sendto(eee->udp_mgmt_sock, udp_buf, msg_len, 0,
               &req.sender_sock, req.sock_len);
        msg_len = 0;
    }

    // dump supernodes -- this table's columns don't match the TAP/MAC/EDGE/HINT layout
    // shared by SUPERNODE FORWARD/PEER TO PEER above (it's a different kind of row: no
    // TAP address, and the position that looks like "HINT" is actually the RTT/weight
    // selection criterion, not a peer description), so it gets its own header instead of
    // reusing the one printed at the very top.
    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "-------------------------------------------------------------------------------------------------------------------------\n");

    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "SUPERNODES\n");
    /* "### |" prefix added purely so this header line gets recognized/highlighted
     * the same way the TAP/MAC/EDGE/HINT header and the IPV6 ROUTES header above
     * do in some terminal clients (a leading "###" seems to trigger that) --
     * added a matching numbered index to each data row below so the column
     * actually lines up, not just the header text. */
    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        " ### | %-24s %1s%1s | %-17s | %-21s | %-15s | %9s | %-24s\n",
                        "SN VER", "L", "A", "MAC", "ADDRESS", "SELECTION", "SEEN", "STARTED (SN LOCAL TIME)");
    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "=======================================================================================================================================\n");
    num = 0;
    HASH_ITER(hh, eee->conf.supernodes, peer, tmpPeer) {
        net = htonl(peer->dev_addr.net_addr);
        snprintf(time_buf, sizeof(time_buf), "%5us", (unsigned int)(now - peer->last_seen));
        if(peer->sn_start_time) {
            /* weight mode: an absolute timestamp on the supernode's own clock, stored
             * verbatim every probe -- see its comment in n2n_typedefs.h. Display it
             * directly; no arithmetic against our own clock here, which is exactly what
             * made this drift by however many seconds had elapsed since the last probe,
             * confirmed live (the same supernode's displayed start time changed on
             * every single console query). */
            strftime(uptime_buf, sizeof(uptime_buf), "%Y/%m/%d %H:%M:%S", localtime(&peer->sn_start_time));
        } else if(peer->uptime) {
            /* legacy --select-rtt path: peer->uptime is a duration as of the last
             * PEER_INFO/PONG (see sn_utils.c's `pi.uptime = now - sss->start_time`), so
             * recover the absolute start time by subtracting it from our current clock.
             * This one *can* drift a little between PONGs, same as it always could --
             * not touched here, only weight mode's now-fixed version above is new. */
            time_t started = now - peer->uptime;
            strftime(uptime_buf, sizeof(uptime_buf), "%Y/%m/%d %H:%M:%S", localtime(&started));
        }
        msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                            "%4u | %-24s %1s%1s | %-17s | %-21s | %-15s | %9s | %-24s\n",
                            ++num,
                            peer->version,
                            (peer->purgeable) ? "" : "l",
                            (peer == eee->curr_sn) ? (eee->sn_wait ? "." : "*" ) : "",
                            is_null_mac(peer->mac_addr) ? "" : macaddr_str(mac_buf, peer->mac_addr),
                            sock_to_cstr(sockbuf, &(peer->sock)),
                            sn_selection_criterion_str(eee, sel_buf, peer),
                            (peer->last_seen) ? time_buf : "",
                            (peer->sn_start_time || peer->uptime) ? uptime_buf : "");

        sendto(eee->udp_mgmt_sock, udp_buf, msg_len, 0,
               &req.sender_sock, req.sock_len);
        msg_len = 0;
    }

    // Stage A IPv6 support: a further table, appended below SUPERNODES, listing
    // eee->learned_routes -- the same data mgmt_routes() exposes over JSON (the
    // "routes" command), just also rendered here for the bare-<enter> plain-text
    // console. SUBNET width and MAC's column offset match the TAP and SUPERNODES
    // tables above (see their comments) so all three line up. HINT is the
    // advertising peer's own dev_desc, the same lookup mgmt_edges_row() already
    // does for the TAP table -- "N/A" if that MAC isn't a currently-known peer
    // (e.g. it only reached us relayed through a supernode we're not directly
    // peered with). There's no IPv6-specific supernode selection (stays
    // IPv4-only, see SN_SELECTION_STRATEGY_WEIGHT), so that column was dropped
    // entirely rather than kept around always reading "N/A".
    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "=======================================================================================================================================\n");
    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "IPV6 ROUTES\n");
    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        " ### | %-27s | %-17s | %-15s | %9s\n",
                        "SUBNET", "MAC", "HINT", "LAST SEEN");
    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "====================================================================================\n");
    sendto(eee->udp_mgmt_sock, udp_buf, msg_len, 0,
           &req.sender_sock, req.sock_len);
    msg_len = 0;

    {
        n2n_learned_route_t *route, *tmpRoute;
        ip6str_t subnet_buf;
        uint32_t num_routes = 0;
        const char *hint;

        HASH_ITER(hh, eee->learned_routes, route, tmpRoute) {
            inet_ntop(AF_INET6, route->subnet.net_addr, subnet_buf, sizeof(subnet_buf));
            snprintf(time_buf, sizeof(time_buf), "%8us", (unsigned int)(now - route->last_seen));
            hint = find_peer_desc_by_mac(eee, route->srcMac);

            msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                                "%4u | %-27s | %-17s | %-15s | %9s\n",
                                ++num_routes,
                                subnet_buf,
                                macaddr_str(mac_buf, route->srcMac),
                                (hint && hint[0]) ? hint : "N/A",
                                time_buf);

            sendto(eee->udp_mgmt_sock, udp_buf, msg_len, 0,
                   &req.sender_sock, req.sock_len);
            msg_len = 0;
        }

        if(num_routes == 0) {
            msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                                "(none learned yet)\n");
            sendto(eee->udp_mgmt_sock, udp_buf, msg_len, 0,
                   &req.sender_sock, req.sock_len);
            msg_len = 0;
        }
    }

    // further stats
    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "====================================================================================\n");

    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "uptime %lu | ",
                        time(NULL) - eee->start_time);

    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "pend_peers %u | ",
                        num_pending_peers);

    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "known_peers %u | ",
                        num_known_peers);

    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "transop %u,%u\n",
                        (unsigned int) eee->transop.tx_cnt,
                        (unsigned int) eee->transop.rx_cnt);

    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "super %u,%u | ",
                        (unsigned int) eee->stats.tx_sup,
                        (unsigned int) eee->stats.rx_sup);

    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "p2p %u,%u\n",
                        (unsigned int) eee->stats.tx_p2p,
                        (unsigned int) eee->stats.rx_p2p);

    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "last_super %ld sec ago | ",
                        (now - eee->last_sup));

    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "last_p2p %ld sec ago\n",
                        (now - eee->last_p2p));

    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "\nType \"help\" to see more commands.\n\n");

    sendto(eee->udp_mgmt_sock, udp_buf, msg_len, 0,
           &req.sender_sock, req.sock_len);
}
