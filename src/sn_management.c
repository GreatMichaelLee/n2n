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

/*
 * This file has a large amount of duplication with the edge_management.c
 * code.  In the fullness of time, they should both be merged
 */


#include <errno.h>       // for errno
#include <stdbool.h>
#include <stdint.h>      // for uint8_t, uint32_t
#include <stdio.h>       // for snprintf, size_t, sprintf, NULL
#include <string.h>      // for memcmp, memcpy, strerror, strncpy
#include <sys/types.h>   // for ssize_t, time_t
#include "management.h"  // for mgmt_req_t, send_reply, mgmt_handler_t, mgmt...
#include "n2n.h"         // for n2n_sn_t, sn_community, peer_info, N2N_SN_PK...
#include "n2n_define.h"    // for N2N_SN_PKTBUF_SIZE, UNPURGEABLE
#include "n2n_typedefs.h"  // for n2n_sn_t, sn_community, peer_info, sn_stats_t
#include "n2n_wire.h"      // for fill_n2nsock
#include "strbuf.h"      // for strbuf_t, STRBUF_INIT
#include "uthash.h"      // for UT_hash_handle, HASH_ITER, HASH_COUNT

#ifdef _WIN32
#include "win32/defs.h"
#else
#include <arpa/inet.h>   // for inet_ntop
#include <sys/socket.h>  // for sendto, socklen_t
#endif


int load_allowed_sn_community (n2n_sn_t *sss); /* defined in sn_utils.c */

static void mgmt_reload_communities (mgmt_req_t *req, strbuf_t *buf) {

    if(req->type!=N2N_MGMT_WRITE) {
        mgmt_error(req, buf, "writeonly");
        return;
    }

    if(!req->sss->community_file) {
        mgmt_error(req, buf, "nofile");
        return;
    }

    int ok = load_allowed_sn_community(req->sss);
    send_json_1uint(req, buf, "row", "ok", ok);
}

static void mgmt_timestamps (mgmt_req_t *req, strbuf_t *buf) {
    size_t msg_len;

    msg_len = snprintf(buf->str, buf->size,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"start_time\":%lu,"
                       "\"last_fwd\":%ld,"
                       "\"last_reg_super\":%ld}\n",
                       req->tag,
                       req->sss->start_time,
                       req->sss->stats.last_fwd,
                       req->sss->stats.last_reg_super);

    send_reply(req, buf, msg_len);
}

static void mgmt_packetstats (mgmt_req_t *req, strbuf_t *buf) {
    size_t msg_len;

    msg_len = snprintf(buf->str, buf->size,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"type\":\"forward\","
                       "\"tx_pkt\":%lu}\n",
                       req->tag,
                       req->sss->stats.fwd);

    send_reply(req, buf, msg_len);

    msg_len = snprintf(buf->str, buf->size,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"type\":\"broadcast\","
                       "\"tx_pkt\":%lu}\n",
                       req->tag,
                       req->sss->stats.broadcast);

    send_reply(req, buf, msg_len);

    msg_len = snprintf(buf->str, buf->size,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"type\":\"reg_super\","
                       "\"rx_pkt\":%lu,"
                       "\"nak\":%lu}\n",
                       req->tag,
                       req->sss->stats.reg_super,
                       req->sss->stats.reg_super_nak);

    /* Note: reg_super_nak is not currently incremented anywhere */

    send_reply(req, buf, msg_len);

    /* Generic errors when trying to sendto() */
    msg_len = snprintf(buf->str, buf->size,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"type\":\"errors\","
                       "\"tx_pkt\":%lu}\n",
                       req->tag,
                       req->sss->stats.errors);

    send_reply(req, buf, msg_len);
}

static void mgmt_communities (mgmt_req_t *req, strbuf_t *buf) {
    size_t msg_len;
    struct sn_community *community, *tmp;
    dec_ip_bit_str_t ip_bit_str = {'\0'};

    HASH_ITER(hh, req->sss->communities, community, tmp) {

        msg_len = snprintf(buf->str, buf->size,
                           "{"
                           "\"_tag\":\"%s\","
                           "\"_type\":\"row\","
                           "\"community\":\"%s\","
                           "\"purgeable\":%i,"
                           "\"is_federation\":%i,"
                           "\"ip4addr\":\"%s\"}\n",
                           req->tag,
                           (community->is_federation) ? "-/-" : community->community,
                           community->purgeable,
                           community->is_federation,
                           (community->auto_ip_net.net_addr == 0) ? "" : ip_subnet_to_str(ip_bit_str, &community->auto_ip_net));

        send_reply(req, buf, msg_len);
    }
}

static void mgmt_edges (mgmt_req_t *req, strbuf_t *buf) {
    size_t msg_len;
    struct sn_community *community, *tmp;
    struct peer_info *peer, *tmpPeer;
    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;
    dec_ip_bit_str_t ip_bit_str = {'\0'};

    HASH_ITER(hh, req->sss->communities, community, tmp) {
        HASH_ITER(hh, community->edges, peer, tmpPeer) {

            msg_len = snprintf(buf->str, buf->size,
                               "{"
                               "\"_tag\":\"%s\","
                               "\"_type\":\"row\","
                               "\"community\":\"%s\","
                               "\"ip4addr\":\"%s\","
                               "\"purgeable\":%i,"
                               "\"macaddr\":\"%s\","
                               "\"sockaddr\":\"%s\","
                               "\"proto\":\"%s\","
                               "\"desc\":\"%s\","
                               "\"last_seen\":%li}\n",
                               req->tag,
                               (community->is_federation) ? "-/-" : community->community,
                               (peer->dev_addr.net_addr == 0) ? "" : ip_subnet_to_str(ip_bit_str, &peer->dev_addr),
                               peer->purgeable,
                               (is_null_mac(peer->mac_addr)) ? "" : macaddr_str(mac_buf, peer->mac_addr),
                               sock_to_cstr(sockbuf, &(peer->sock)),
                               ((peer->socket_fd >= 0) && (peer->socket_fd != req->sss->sock)) ? "TCP" : "UDP",
                               peer->dev_desc,
                               peer->last_seen);

            send_reply(req, buf, msg_len);
        }
    }
}

/* Stage A IPv6 support: read-only view of every community's ->routes, cached
 * in sn_utils.c's MSG_TYPE_COMMUNITY_ROUTE_ADV handling as it relays these
 * advertisements between edges. Mirrors edge_management.c's mgmt_routes(),
 * plus a "community" field since a supernode spans more than one. As with
 * the edge side, this supernode never applies any of it -- purely a mirror
 * for whichever platform integration layer wants to poll it. */
/* Look up a directly-registered edge's dev_desc by MAC within one community
 * -- used to give the IPV6 ROUTES table a human-readable HINT column instead
 * of a bare MAC. NULL if that MAC isn't directly registered with THIS
 * supernode in that community (e.g. it only reached us relayed through a
 * federation peer -- see REMOTE EDGES below for that case). */
static const char *find_edge_desc_by_mac (struct sn_community *community, const n2n_mac_t mac) {
    struct peer_info *peer, *tmpPeer;

    HASH_ITER(hh, community->edges, peer, tmpPeer) {
        if(memcmp(peer->mac_addr, mac, N2N_MAC_SIZE) == 0)
            return (const char *)peer->dev_desc;
    }
    return NULL;
}

static void mgmt_routes (mgmt_req_t *req, strbuf_t *buf) {
    size_t msg_len;
    struct sn_community *community, *tmp;
    n2n_learned_route_t *route, *tmpRoute;
    macstr_t mac_buf;
    ip6str_t subnet_buf;
    const char *hint;

    HASH_ITER(hh, req->sss->communities, community, tmp) {
        HASH_ITER(hh, community->routes, route, tmpRoute) {

            inet_ntop(AF_INET6, route->subnet.net_addr, subnet_buf, sizeof(subnet_buf));
            hint = find_edge_desc_by_mac(community, route->srcMac);

            msg_len = snprintf(buf->str, buf->size,
                               "{"
                               "\"_tag\":\"%s\","
                               "\"_type\":\"row\","
                               "\"community\":\"%s\","
                               "\"macaddr\":\"%s\","
                               "\"subnet\":\"%s/%u\","
                               "\"hint\":\"%s\","
                               "\"last_seen\":%li}\n",
                               req->tag,
                               (community->is_federation) ? "-/-" : community->community,
                               macaddr_str(mac_buf, route->srcMac),
                               subnet_buf,
                               route->subnet.net_bitlen,
                               hint ? hint : "",
                               route->last_seen);

            send_reply(req, buf, msg_len);
        }
    }
}

/* User request 2026-09-17: this supernode's own "edges" JSON/plain-text
 * only shows edges registered directly with it. comm->assoc tracks, per
 * community, which OTHER supernode each edge we've heard about (but never
 * registered with us) is actually attached to -- learned for free as a side
 * effect of ordinary cross-site traffic/relay (see sn_utils.c). Exposing it
 * here means querying any one supernode in the federation can show the
 * whole fleet's edges. */
static void mgmt_remote_edges (mgmt_req_t *req, strbuf_t *buf) {
    size_t msg_len;
    struct sn_community *community, *tmp;
    node_supernode_association_t *assoc, *tmp_assoc;
    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;

    HASH_ITER(hh, req->sss->communities, community, tmp) {
        HASH_ITER(hh, community->assoc, assoc, tmp_assoc) {
            n2n_sock_t via_sn;

            /* assoc->sock is a raw OS struct sockaddr (it's filled straight from
             * recvfrom()'s sender address, see sn_utils.c), not n2n's own
             * n2n_sock_t -- sock_to_cstr() only takes the latter, hence the
             * conversion via fill_n2nsock() (the same helper edge_utils.c
             * already uses for the same reason). */
            fill_n2nsock(&via_sn, &(assoc->sock));

            msg_len = snprintf(buf->str, buf->size,
                               "{"
                               "\"_tag\":\"%s\","
                               "\"_type\":\"row\","
                               "\"community\":\"%s\","
                               "\"macaddr\":\"%s\","
                               "\"via_supernode\":\"%s\","
                               "\"last_seen\":%li}\n",
                               req->tag,
                               (community->is_federation) ? "-/-" : community->community,
                               macaddr_str(mac_buf, assoc->mac),
                               sock_to_cstr(sockbuf, &via_sn),
                               assoc->last_seen);

            send_reply(req, buf, msg_len);
        }
    }
}

// Forward define so we can include this in the mgmt_handlers[] table
static void mgmt_help (mgmt_req_t *req, strbuf_t *buf);

static const mgmt_handler_t mgmt_handlers[] = {
    { .cmd = "supernodes", .help = "Reserved for edge", .func = mgmt_unimplemented},

    { .cmd = "stop", .flags = FLAG_WROK, .help = "Gracefully exit edge", .func = mgmt_stop},
    { .cmd = "verbose", .flags = FLAG_WROK, .help = "Manage verbosity level", .func = mgmt_verbose},
    { .cmd = "reload_communities", .flags = FLAG_WROK, .help = "Reloads communities and user's public keys", .func = mgmt_reload_communities},
    { .cmd = "communities", .help = "List current communities", .func = mgmt_communities},
    { .cmd = "edges", .help = "List current edges/peers", .func = mgmt_edges},
    { .cmd = "routes", .help = "List learned IPv6 community routes", .func = mgmt_routes},
    { .cmd = "remote_edges", .help = "List edges registered with other federated supernodes", .func = mgmt_remote_edges},
    { .cmd = "timestamps", .help = "Event timestamps", .func = mgmt_timestamps},
    { .cmd = "packetstats", .help = "Traffic statistics", .func = mgmt_packetstats},
    { .cmd = "help", .flags = FLAG_WROK, .help = "Show JSON commands", .func = mgmt_help},
};

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

// TODO: DRY
static void handleMgmtJson (mgmt_req_t *req, char *udp_buf, const int recvlen) {

    strbuf_t *buf;
    char cmdlinebuf[80];

    /* save a copy of the commandline before we reuse the udp_buf */
    strncpy(cmdlinebuf, udp_buf, sizeof(cmdlinebuf)-1);
    cmdlinebuf[sizeof(cmdlinebuf)-1] = 0;

    traceEvent(TRACE_DEBUG, "mgmt json %s", cmdlinebuf);

    /* we reuse the buffer already on the stack for all our strings */
    // xx
    STRBUF_INIT(buf, udp_buf, N2N_SN_PKTBUF_SIZE);

    if(!mgmt_req_init2(req, buf, (char *)&cmdlinebuf)) {
        // if anything failed during init
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

static int sendto_mgmt (n2n_sn_t *sss,
                        const struct sockaddr *sender_sock, socklen_t sock_size,
                        const uint8_t *mgmt_buf,
                        size_t mgmt_size) {

    ssize_t r = sendto(sss->mgmt_sock, (void *)mgmt_buf, mgmt_size, 0 /*flags*/,
                       sender_sock, sock_size);

    if(r <= 0) {
        ++(sss->stats.errors);
        traceEvent(TRACE_ERROR, "sendto_mgmt : sendto failed. %s", strerror(errno));
        return -1;
    }

    return 0;
}

int process_mgmt (n2n_sn_t *sss,
                  const struct sockaddr *sender_sock, socklen_t sock_size,
                  char *mgmt_buf,
                  size_t mgmt_size,
                  time_t now) {

    char resbuf[N2N_SN_PKTBUF_SIZE];
    size_t ressize = 0;
    mgmt_req_t req;
    uint32_t num_edges = 0;
    uint32_t num_comm = 0;
    uint32_t num = 0;
    struct sn_community *community, *tmp;
    struct peer_info *peer, *tmpPeer;
    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;
    char time_buf[10]; /* 9 digits + 1 terminating zero */
    dec_ip_bit_str_t ip_bit_str = {'\0'};

    traceEvent(TRACE_DEBUG, "process_mgmt");

    req.eee = NULL;
    req.sss = sss;
    req.mgmt_sock = sss->mgmt_sock;
    req.keep_running = sss->keep_running;
    req.mgmt_password_hash = sss->mgmt_password_hash;
    memcpy(&req.sender_sock, sender_sock, sock_size);
    req.sock_len = sock_size;

    /* avoid parsing any uninitialized junk from the stack */
    mgmt_buf[mgmt_size] = 0;

    // process input, if any
    if((0 == memcmp(mgmt_buf, "help", 4)) || (0 == memcmp(mgmt_buf, "?", 1))) {
        ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                            "Help for supernode management console:\n"
                            "\thelp                 | This help message\n"
                            "\treload_communities   | Reloads communities and user's public keys\n"
                            "\t<enter>              | Display status and statistics\n");
        sendto_mgmt(sss, sender_sock, sock_size, (const uint8_t *) resbuf, ressize);
        return 0; /* no status output afterwards */
    }

    if(0 == memcmp(mgmt_buf, "reload_communities", 18)) {
        if(!sss->community_file) {
            ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                                "No community file provided (-c command line option)\n");
            sendto_mgmt(sss, sender_sock, sock_size, (const uint8_t *) resbuf, ressize);
            return 0; /* no status output afterwards */
        }
        traceEvent(TRACE_NORMAL, "'reload_communities' command");

        if(load_allowed_sn_community(sss)) {
            ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                                "Error while re-loading community file (not found or no valid content)\n");
            sendto_mgmt(sss, sender_sock, sock_size, (const uint8_t *) resbuf, ressize);
            return 0; /* no status output afterwards */
        }
        ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                            "OK.\n");
        sendto_mgmt(sss, sender_sock, sock_size, (const uint8_t *) resbuf, ressize);
        return 0; /* no status output afterwards */
    }

    if((mgmt_buf[0] >= 'a' && mgmt_buf[0] <= 'z') && (mgmt_buf[1] == ' ')) {
        /* this is a JSON request -- note the &&: '>= a || <= z' (the previous condition
         * here) is true for every possible byte value (every byte is either >= 'a' or
         * <= 'z', there's no gap), making it a no-op that left mgmt_buf[1] == ' ' as the
         * only real gate. A short/empty query (e.g. a bare newline from `echo -e '' | nc`)
         * only fills mgmt_buf[0], leaving mgmt_buf[1] as whatever was already in the
         * buffer from a previous request -- if that leftover byte happened to be a space,
         * the plain-text status dump below was skipped in favor of handleMgmtJson(),
         * which silently produces no output for a non-JSON payload. Confirmed live: this
         * intermittently made the whole management port on a live supernode appear to
         * stop responding to plain-text queries entirely, with nothing in the log to
         * explain it. edge_management.c's equivalent check already uses &&. */
        handleMgmtJson(&req, mgmt_buf, mgmt_size);
        return 0;
    }

    // output current status

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        " ### | TAP                 | MAC               | EDGE                      | HINT            | LAST SEEN\n");
    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "========================================================================================================\n");
    HASH_ITER(hh, sss->communities, community, tmp) {
        if(num_comm)
            ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                                "--------------------------------------------------------------------------------------------------------\n");
        num_comm++;
        num_edges += HASH_COUNT(community->edges);

        ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                            "%s '%s'\n",
                            (community->is_federation) ? "FEDERATION" : ((community->purgeable) ? "COMMUNITY" : "FIXED NAME COMMUNITY"),
                            (community->is_federation) ? "-/-" : community->community);
        sendto_mgmt(sss, sender_sock, sock_size, (const uint8_t *) resbuf, ressize);
        ressize = 0;

        num = 0;
        HASH_ITER(hh, community->edges, peer, tmpPeer) {
            sprintf(time_buf, "%8us", (unsigned int)(now - peer->last_seen));
            ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                                "%4u | %-19s | %-17s | %-21s %-3s | %-15s | %9s\n",
                                ++num,
                                (peer->dev_addr.net_addr == 0) ? ((peer->purgeable) ? "" : "-l") : ip_subnet_to_str(ip_bit_str, &peer->dev_addr),
                                (is_null_mac(peer->mac_addr)) ? "" : macaddr_str(mac_buf, peer->mac_addr),
                                sock_to_cstr(sockbuf, &(peer->sock)),
                                ((peer->socket_fd >= 0) && (peer->socket_fd != sss->sock)) ? "TCP" : "",
                                peer->dev_desc,
                                (peer->last_seen) ? time_buf : "");

            sendto_mgmt(sss, sender_sock, sock_size, (const uint8_t *) resbuf, ressize);
            ressize = 0;
        }
    }
    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "========================================================================================================\n");

    /* User request 2026-09-17: this supernode's own edges table above only
     * shows edges registered directly with it -- an edge registered with a
     * federation peer supernode never appears here at all, even though this
     * supernode does learn *of* it (comm->assoc, populated for free as a
     * side effect of ordinary cross-site traffic/relay -- see sn_utils.c's
     * MSG_TYPE_COMMUNITY_ROUTE_ADV handling for another consumer of the same
     * data). Surfacing it means querying any one supernode in the federation
     * can show the whole fleet's edges, not just the ones attached to it.
     * Placed directly after the local-edges table above (not after IPV6
     * ROUTES) since both are fundamentally "which edges exist" -- IPv4
     * local/remote belong next to each other, IPv6 is a separate concern.
     *
     * Reuses the exact same row format string as the local-edges table
     * above (not just matching widths by hand) so the two are guaranteed to
     * stay column-aligned: TAP has no equivalent here (no per-row "-"), so
     * it's blank; EDGE's slot carries COMMUNITY instead, since which
     * supernode an edge is behind is now the *section* header rather than a
     * per-row value (see below); PROTO has no meaning here either.
     *
     * A federation can have more than 2 supernodes, so edges attached
     * elsewhere can be split across more than one *other* supernode -- one
     * flat table with a per-row "VIA SUPERNODE" column doesn't make that
     * obvious at a glance. Instead: a separate sub-table per distinct remote
     * supernode actually seen, each headed by that supernode's own address
     * (there's no friendlier name available for one we never registered
     * with ourselves). HINT is the edge's own dev_desc if this supernode
     * happened to learn it (only available via the REGISTER_SUPER-triggered
     * caller of update_node_supernode_association(), not the PEER_INFO one
     * -- see its comment), "N/A" otherwise. */
    {
        node_supernode_association_t *assoc, *tmp_assoc;
        n2n_sock_str_t remote_sns[16];
        int num_remote_sns = 0;
        int i;
        uint32_t num_remote_total = 0;

        HASH_ITER(hh, sss->communities, community, tmp) {
            HASH_ITER(hh, community->assoc, assoc, tmp_assoc) {
                n2n_sock_t via_sn;
                n2n_sock_str_t via_str;

                num_remote_total++;
                fill_n2nsock(&via_sn, &(assoc->sock));
                sock_to_cstr(via_str, &via_sn);

                for(i = 0; i < num_remote_sns; i++) {
                    if(0 == strcmp(remote_sns[i], via_str))
                        break;
                }
                if((i == num_remote_sns) && (num_remote_sns < 16)) {
                    strncpy(remote_sns[num_remote_sns], via_str, sizeof(n2n_sock_str_t));
                    num_remote_sns++;
                }
            }
        }

        if(num_remote_total == 0) {
            ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                                "REMOTE EDGES (VIA FEDERATION)\n");
            ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                                "(none known yet)\n");
            sendto_mgmt(sss, sender_sock, sock_size, (const uint8_t *) resbuf, ressize);
            ressize = 0;
        }

        for(i = 0; i < num_remote_sns; i++) {
            uint32_t num_this_sn = 0;
            const char *hint;

            ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                                "REMOTE EDGES VIA SUPERNODE %s\n", remote_sns[i]);
            ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                                " ### | %-19s | %-17s | %-21s %-3s | %-15s | %9s\n",
                                "TAP", "MAC", "COMMUNITY", "", "HINT", "LAST SEEN");
            ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                                "========================================================================================================\n");
            sendto_mgmt(sss, sender_sock, sock_size, (const uint8_t *) resbuf, ressize);
            ressize = 0;

            HASH_ITER(hh, sss->communities, community, tmp) {
                HASH_ITER(hh, community->assoc, assoc, tmp_assoc) {
                    n2n_sock_t via_sn;
                    n2n_sock_str_t via_str;

                    fill_n2nsock(&via_sn, &(assoc->sock));
                    sock_to_cstr(via_str, &via_sn);
                    if(0 != strcmp(via_str, remote_sns[i]))
                        continue;

                    sprintf(time_buf, "%8us", (unsigned int)(now - assoc->last_seen));
                    hint = (const char *)assoc->dev_desc;

                    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                                        "%4u | %-19s | %-17s | %-21s %-3s | %-15s | %9s\n",
                                        ++num_this_sn,
                                        "",
                                        macaddr_str(mac_buf, assoc->mac),
                                        (community->is_federation) ? "-/-" : community->community,
                                        "",
                                        (hint && hint[0]) ? hint : "N/A",
                                        time_buf);

                    sendto_mgmt(sss, sender_sock, sock_size, (const uint8_t *) resbuf, ressize);
                    ressize = 0;
                }
            }

            ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                                "========================================================================================================\n");
            sendto_mgmt(sss, sender_sock, sock_size, (const uint8_t *) resbuf, ressize);
            ressize = 0;
        }
    }

    /* Stage A IPv6 support: appended after both edges tables above (local
     * and remote) rather than between them -- IPv4 local/remote are the
     * same kind of thing and belong adjacent to each other; IPv6 routing is
     * a separate concern. Lists every IPv6 CIDR any edge in any community
     * has advertised via MSG_TYPE_COMMUNITY_ROUTE_ADV (cached in
     * comm->routes as this supernode relays them -- see sn_utils.c).
     * SUBNET's width matches TAP's above so MAC starts at the same column
     * in every table on this console. HINT is the advertising edge's own
     * dev_desc if it's directly registered with this supernode (looked up
     * in the same community's ->edges), "N/A" otherwise -- there is no
     * IPv6-specific supernode selection (stays IPv4-only, see the
     * SN_SELECTION_STRATEGY_WEIGHT work), so that column was dropped
     * entirely rather than kept around always reading "N/A". */
    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "IPV6 ROUTES\n");
    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        " ### | %-19s | %-17s | %-16s | %-15s | %9s\n",
                        "SUBNET", "MAC", "COMMUNITY", "HINT", "LAST SEEN");
    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "===============================================================================================\n");
    sendto_mgmt(sss, sender_sock, sock_size, (const uint8_t *) resbuf, ressize);
    ressize = 0;

    {
        n2n_learned_route_t *route, *tmpRoute;
        ip6str_t subnet_buf;
        uint32_t num_routes = 0;
        const char *hint;

        HASH_ITER(hh, sss->communities, community, tmp) {
            HASH_ITER(hh, community->routes, route, tmpRoute) {
                inet_ntop(AF_INET6, route->subnet.net_addr, subnet_buf, sizeof(subnet_buf));
                sprintf(time_buf, "%8us", (unsigned int)(now - route->last_seen));
                hint = find_edge_desc_by_mac(community, route->srcMac);

                ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                                    "%4u | %-19s | %-17s | %-16s | %-15s | %9s\n",
                                    ++num_routes,
                                    subnet_buf,
                                    macaddr_str(mac_buf, route->srcMac),
                                    (community->is_federation) ? "-/-" : community->community,
                                    (hint && hint[0]) ? hint : "N/A",
                                    time_buf);

                sendto_mgmt(sss, sender_sock, sock_size, (const uint8_t *) resbuf, ressize);
                ressize = 0;
            }
        }

        if(num_routes == 0) {
            ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                                "(none learned yet)\n");
            sendto_mgmt(sss, sender_sock, sock_size, (const uint8_t *) resbuf, ressize);
            ressize = 0;
        }
    }

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "===============================================================================================\n");

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "uptime %lu | ", (now - sss->start_time));

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "edges %u | ",
                        num_edges);

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "reg_sup %u | ",
                        (unsigned int) sss->stats.reg_super);

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "reg_nak %u | ",
                        (unsigned int) sss->stats.reg_super_nak);

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "errors %u \n",
                        (unsigned int) sss->stats.errors);

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "fwd %u | ",
                        (unsigned int) sss->stats.fwd);

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "broadcast %u | ",
                        (unsigned int) sss->stats.broadcast);

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "cur_cmnts %u\n", HASH_COUNT(sss->communities));

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "last_fwd  %lu sec ago | ",
                        (long unsigned int) (now - sss->stats.last_fwd));

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "last reg  %lu sec ago\n\n",
                        (long unsigned int) (now - sss->stats.last_reg_super));

    sendto_mgmt(sss, sender_sock, sock_size, (const uint8_t *) resbuf, ressize);

    return 0;
}
