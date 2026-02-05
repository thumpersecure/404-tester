/* TCP/IP fingerprint editor - Configurable Packet Header Engine

Copyright (C) 2025 - 404 Contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_packet.h>
#include <linux/pkt_cls.h>
#include <stddef.h>
#include <stdint.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Compile with:

    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/ -I/usr/include/linux -c ttl_editor.c -o <output>.o

*/

/* Attach with:

    sudo tc qdisc add dev <interface> clsact
    sudo tc filter add dev <interface> egress bpf da obj <output>.o sec classifier

*/

/* Remove with:

    sudo tc filter del dev <interface> egress
    sudo tc qdisc del dev <interface> clsact

*/

/*
 * Configurable TCP/IP Fingerprint Configuration Structure
 *
 * This structure is stored in a BPF map and can be updated from userspace
 * to dynamically change fingerprint characteristics per OS profile.
 *
 * OS Profiles:
 *   0 = Windows (TTL=128, no timestamps, MSS-NOP-WS-NOP-NOP-SACK)
 *   1 = Linux   (TTL=64, timestamps, MSS-SACK-TS-NOP-WS)
 *   2 = macOS   (TTL=64, timestamps, MSS-NOP-WS-NOP-NOP-TS-SACK-EOL)
 *   3 = Custom  (user-defined values)
 */
struct fingerprint_config {
    __u8  os_profile;           // 0=Windows, 1=Linux, 2=macOS, 3=Custom
    __u8  ttl;                  // IP TTL (Windows=128, Linux/macOS=64)
    __u8  hop_limit;            // IPv6 Hop Limit (same as TTL)
    __u8  ip_tos;               // IP Type of Service / DSCP
    __u16 mss;                  // TCP Maximum Segment Size
    __u16 window_size;          // TCP Window Size
    __u8  window_scale;         // TCP Window Scale factor
    __u8  timestamps_enabled;   // 0=disabled (Windows), 1=enabled (Unix)
    __u8  randomize_ip_id;      // Randomize IP ID field
    __u8  randomize_seq;        // Randomize TCP initial sequence
    __u8  randomize_ipv6_flow;  // Randomize IPv6 flow label
    __u8  df_flag;              // Don't Fragment flag (1=set, 0=clear)
    __u8  reserved[2];          // Padding for alignment
} __attribute__((packed));

/* BPF map for protocol counters (telemetry) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, long);
} protocol_counter SEC(".maps");

/* BPF map for configurable fingerprint settings
 * Key 0 contains the active fingerprint_config
 * Updated from userspace via bpf() syscall or libbpf
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct fingerprint_config);
} fingerprint_settings SEC(".maps");

/* Default fallback values (Windows profile) - used if map not populated */
#define DEFAULT_TTL 128
#define DEFAULT_TCP_WINDOW_SIZE 65535
#define DEFAULT_TCP_INITIAL_SEQ 0x12345678
#define DEFAULT_TCP_WINDOW_SCALE 8
#define DEFAULT_TCP_MSS 1460
#define DEFAULT_IP_TOS 0x00

/* TCP flags */
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_ACK 0x10

/* TCP Options kind numbers
 *
 * TCP Options Order by OS (for SYN packets):
 *   Windows:  MSS, NOP, WS, NOP, NOP, SACK_PERM
 *   Linux:    MSS, SACK_PERM, TS, NOP, WS
 *   macOS:    MSS, NOP, WS, NOP, NOP, TS, SACK_PERM, EOL
 *
 * Note: Full TCP options reordering requires packet reconstruction which is
 * complex in eBPF. Current implementation modifies option VALUES in place.
 * For complete stealth, consider implementing options reordering in userspace
 * using raw sockets or nftables with packet mangling.
 */
#define TCPOPT_EOL 0
#define TCPOPT_NOP 1
#define TCPOPT_MSS 2
#define TCPOPT_WINDOW_SCALE 3
#define TCPOPT_SACK_PERMITTED 4
#define TCPOPT_TIMESTAMP 8

const int RETURN_CODE = TC_ACT_OK;

/* Helper to get fingerprint config from map with fallback defaults */
static __always_inline struct fingerprint_config get_fingerprint_config(void)
{
    __u32 key = 0;
    struct fingerprint_config *cfg = bpf_map_lookup_elem(&fingerprint_settings, &key);

    if (cfg) {
        return *cfg;
    }

    /* Return Windows defaults if map not populated */
    struct fingerprint_config defaults = {
        .os_profile = 0,                    // Windows
        .ttl = DEFAULT_TTL,                 // 128
        .hop_limit = DEFAULT_TTL,           // 128
        .ip_tos = DEFAULT_IP_TOS,           // 0x00
        .mss = DEFAULT_TCP_MSS,             // 1460
        .window_size = DEFAULT_TCP_WINDOW_SIZE, // 65535
        .window_scale = DEFAULT_TCP_WINDOW_SCALE, // 8
        .timestamps_enabled = 0,            // Windows: no timestamps
        .randomize_ip_id = 1,
        .randomize_seq = 1,
        .randomize_ipv6_flow = 1,
        .df_flag = 1,                       // Windows sets DF
        .reserved = {0, 0}
    };
    return defaults;
}

static __always_inline int parse_ipv4(void *data, void *data_end);
static __always_inline int parse_ipv6(void *data, void *data_end);
static __always_inline void spoof_tcp_fingerprint(struct __sk_buff *skb, void *data, void *data_end, __u32 tcp_offset, struct fingerprint_config *cfg);

SEC("classifier")

int tc_counter(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* Load fingerprint configuration from map */
    struct fingerprint_config cfg = get_fingerprint_config();

    struct ethhdr *eth = data;
    __u32 network_header_offset = sizeof(*eth);

    if (data + network_header_offset > data_end)
        return RETURN_CODE;

    __u16 h_proto = eth->h_proto;
    int protocol_index = 0;

    if (h_proto == __constant_htons(ETH_P_IP)) {
        protocol_index = parse_ipv4(data + network_header_offset, data_end);
    } else if (h_proto == __constant_htons(ETH_P_IPV6)) {
        protocol_index = parse_ipv6(data + network_header_offset, data_end);
    } else {
        protocol_index = 0;
    }

    if (protocol_index == 0)
        return RETURN_CODE;

    __u32 key = (__u32)protocol_index;
    long *protocol_count = bpf_map_lookup_elem(&protocol_counter, &key);
    if (protocol_count) {
        __sync_fetch_and_add(protocol_count, 1);
    }

    if (h_proto == __constant_htons(ETH_P_IP)) {
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        struct iphdr *ip_header = data + network_header_offset;

        if ((void *)&ip_header[1] <= data_end) {
            __u8 old_ttl = ip_header->ttl;
            __u8 new_ttl = cfg.ttl;  /* Use configurable TTL */
            __u8 ip_protocol = ip_header->protocol;
            __u8 old_tos = ip_header->tos;
            __u16 old_id = bpf_ntohs(ip_header->id);

            /* Apply configurable IP TOS */
            if (old_tos != cfg.ip_tos) {
                __u32 tos_offset = network_header_offset + offsetof(struct iphdr, tos);
                __u8 new_tos = cfg.ip_tos;
                bpf_skb_store_bytes(skb, tos_offset, &new_tos, 1, 0);

                // Re-fetch after modification (do this a lot, more than you would think)
                data = (void *)(long)skb->data;
                data_end = (void *)(long)skb->data_end;
                ip_header = data + network_header_offset;

                if ((void *)&ip_header[1] > data_end) {
                    return TC_ACT_SHOT;
                }
            }

            /* Configurable IP ID randomization */
            if (cfg.randomize_ip_id && !(bpf_ntohs(ip_header->frag_off) & 0x1FFF)) {
                __u64 timestamp = bpf_ktime_get_ns();
                __u16 new_id = (__u16)(timestamp ^ (timestamp >> 16) ^ old_id);
                __u32 id_offset = network_header_offset + offsetof(struct iphdr, id);
                __be16 new_id_be = bpf_htons(new_id);
                bpf_skb_store_bytes(skb, id_offset, &new_id_be, 2, 0);

                data = (void *)(long)skb->data;
                data_end = (void *)(long)skb->data_end;
                ip_header = data + network_header_offset;

                if ((void *)&ip_header[1] > data_end) {
                    return TC_ACT_SHOT;
                }
            }

            if (old_ttl != new_ttl) {

                int current_len = skb->len;

                if (bpf_skb_change_tail(skb, current_len, 0) != 0) {
                    return TC_ACT_SHOT;
                }

                data = (void *)(long)skb->data;
                data_end = (void *)(long)skb->data_end;
                ip_header = data + network_header_offset;

                if ((void *)&ip_header[1] > data_end) {
                    return TC_ACT_SHOT;
                }

                __u32 ttl_offset = network_header_offset + offsetof(struct iphdr, ttl);
                if (bpf_skb_store_bytes(skb, ttl_offset, &new_ttl, 1, 0) != 0) {
                    return TC_ACT_SHOT;
                }

                data = (void *)(long)skb->data;
                data_end = (void *)(long)skb->data_end;
                ip_header = data + network_header_offset;

                if ((void *)&ip_header[1] <= data_end) {

                    ip_header->check = 0;

                    __u32 csum = 0;
                    __u16 *buf = (__u16 *)ip_header;
                    __u8 ihl = ip_header->ihl;

                    if (ihl < 5) ihl = 5;
                    if (ihl > 15) ihl = 15;

                    __u32 words = ihl * 2;

                    #pragma unroll
                    for (__u32 i = 0; i < 30; i++) {
                        if (i >= words) break;
                        if ((void *)(buf + i + 1) > data_end) break;
                        csum += bpf_ntohs(buf[i]);
                    }

                    csum = (csum & 0xFFFF) + (csum >> 16);
                    csum = (csum & 0xFFFF) + (csum >> 16);
                    ip_header->check = bpf_htons((__u16)~csum);
                }
            }

            if (ip_protocol == IPPROTO_TCP) {

                data = (void *)(long)skb->data;
                data_end = (void *)(long)skb->data_end;
                ip_header = data + network_header_offset;

                if ((void *)&ip_header[1] <= data_end) {
                    __u8 ihl = ip_header->ihl;
                    if (ihl < 5) ihl = 5;
                    if (ihl > 15) ihl = 15;
                    __u32 tcp_offset = network_header_offset + (ihl * 4);
                    spoof_tcp_fingerprint(skb, data, data_end, tcp_offset, &cfg);
                }
            }
        }
    }

    if (h_proto == __constant_htons(ETH_P_IPV6)) {
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        struct ipv6hdr *ip6_header = data + network_header_offset;

        if ((void *)&ip6_header[1] <= data_end) {
            __u8 old_hl = ip6_header->hop_limit;
            __u8 new_hl = cfg.hop_limit;  /* Use configurable hop limit */
            __u32 old_flow = bpf_ntohl(ip6_header->flow_lbl[0] |
                                       (ip6_header->flow_lbl[1] << 8) |
                                       (ip6_header->flow_lbl[2] << 16));

            /* Configurable IPv6 flow label randomization */
            if (cfg.randomize_ipv6_flow) {
                __u64 timestamp = bpf_ktime_get_ns();
                __u32 new_flow = (__u32)(timestamp ^ (timestamp >> 20)) & 0x000FFFFF;

                __u32 version_tc = (ip6_header->priority << 4) | (ip6_header->flow_lbl[0] & 0xF0);
                __u32 new_vtf = (6 << 28) | (version_tc << 20) | new_flow;
                __be32 new_vtf_be = bpf_htonl(new_vtf);

                __u32 vtf_offset = network_header_offset + 0;
                bpf_skb_store_bytes(skb, vtf_offset, &new_vtf_be, 4, 0);

                data = (void *)(long)skb->data;
                data_end = (void *)(long)skb->data_end;
                ip6_header = data + network_header_offset;

                if ((void *)&ip6_header[1] > data_end) {
                    return TC_ACT_SHOT;
                }
            }

            if (old_hl != new_hl) {

                int current_len = skb->len;

                if (bpf_skb_change_tail(skb, current_len, 0) != 0) {
                    return TC_ACT_SHOT;
                }

                data = (void *)(long)skb->data;
                data_end = (void *)(long)skb->data_end;
                ip6_header = data + network_header_offset;

                if ((void *)&ip6_header[1] > data_end) {
                    return TC_ACT_SHOT;
                }

                __u32 hl_offset = network_header_offset + offsetof(struct ipv6hdr, hop_limit);
                if (bpf_skb_store_bytes(skb, hl_offset, &new_hl, 1, 0) != 0) {
                    return TC_ACT_SHOT;
                }

                data = (void *)(long)skb->data;
                data_end = (void *)(long)skb->data_end;
                ip6_header = data + network_header_offset;

                if ((void *)&ip6_header[1] > data_end) {
                    return TC_ACT_SHOT;
                }

                __u8 next_header = ip6_header->nexthdr;
                if (next_header == IPPROTO_UDP) {
                    __u32 udp_offset = network_header_offset + sizeof(struct ipv6hdr);

                    __u32 udp_csum_offset = udp_offset + 6;

                    if ((void *)(data + udp_offset + 8) <= data_end) {
                        __u16 zero_csum = 0;
                        bpf_skb_store_bytes(skb, udp_csum_offset, &zero_csum, 2, 0);
                    }
                } else if (next_header == IPPROTO_TCP) {
                    __u32 tcp_offset = network_header_offset + sizeof(struct ipv6hdr);
                    spoof_tcp_fingerprint(skb, data, data_end, tcp_offset, &cfg);
                }
            }
        }
    }

    return RETURN_CODE;
}

static __always_inline int parse_ipv4(void *ip_data, void *data_end)
{
    struct iphdr *ip_header = ip_data;
    if ((void *)&ip_header[1] > data_end)
        return 0;
    return ip_header->protocol;
}

static __always_inline int parse_ipv6(void *ipv6_data, void *data_end)
{
    struct ipv6hdr *ip6_header = ipv6_data;
    if ((void *)&ip6_header[1] > data_end)
        return 0;
    return ip6_header->nexthdr;
}

struct tcphdr_min {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __u8 doff_res;
    __u8 flags;
    __be16 window;
    __sum16 check;
    __be16 urg_ptr;
} __attribute__((packed));

/*
 * Spoof TCP fingerprint based on configurable profile settings.
 *
 * This function modifies TCP header fields and options to match the target
 * OS fingerprint specified in the configuration:
 *
 * - Window size: Set to profile-specified value
 * - Initial sequence number: Randomized or fixed based on config
 * - MSS: Set to profile-specified value (commonly 1460 for Ethernet)
 * - Window scale: Set to profile-specified value
 * - Timestamps: Only modified if enabled in config (Unix=yes, Windows=no)
 *
 * TCP Options Order Note:
 *   Full TCP options reordering (changing the order of options in the packet)
 *   would require packet reconstruction which is complex in eBPF TC hooks.
 *   Current implementation modifies option VALUES while preserving original order.
 *
 *   For complete OS fingerprint emulation, the TCP options order should match:
 *     Windows:  MSS, NOP, WS, NOP, NOP, SACK_PERM
 *     Linux:    MSS, SACK_PERM, TS, NOP, WS
 *     macOS:    MSS, NOP, WS, NOP, NOP, TS, SACK_PERM, EOL
 *
 *   Consider implementing full options reordering in userspace using raw sockets
 *   or nftables packet mangling for complete stealth.
 */
static __always_inline void spoof_tcp_fingerprint(struct __sk_buff *skb, void *data, void *data_end, __u32 tcp_offset, struct fingerprint_config *cfg)
{

    struct tcphdr_min *tcp = data + tcp_offset;
    if ((void *)&tcp[1] > data_end) {
        return;
    }

    __u8 tcp_flags = tcp->flags;
    __u32 old_seq = bpf_ntohl(tcp->seq);
    __u16 old_window = bpf_ntohs(tcp->window);

    int is_syn = (tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_ACK);

    /* Apply configurable window size */
    __u16 new_window = cfg->window_size;
    if (old_window != new_window) {
        __u32 window_offset = tcp_offset + offsetof(struct tcphdr_min, window);
        __be16 new_window_be = bpf_htons(new_window);
        bpf_skb_store_bytes(skb, window_offset, &new_window_be, 2, 0);
    }

    if (is_syn) {
        /* Configurable sequence number randomization */
        __u32 new_seq;
        if (cfg->randomize_seq) {
            __u64 timestamp = bpf_ktime_get_ns();
            new_seq = (__u32)(timestamp ^ (timestamp >> 32) ^ old_seq ^ DEFAULT_TCP_INITIAL_SEQ);
        } else {
            new_seq = DEFAULT_TCP_INITIAL_SEQ;
        }
        if (old_seq != new_seq) {
            __u32 seq_offset = tcp_offset + offsetof(struct tcphdr_min, seq);
            __be32 new_seq_be = bpf_htonl(new_seq);
            bpf_skb_store_bytes(skb, seq_offset, &new_seq_be, 4, 0);
        }

        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        tcp = data + tcp_offset;
        if ((void *)&tcp[1] > data_end) {
            return;
        }

        __u8 doff = (tcp->doff_res >> 4) & 0x0F;
        if (doff < 5) doff = 5;
        if (doff > 15) doff = 15;
        __u32 tcp_header_len = doff * 4;
        __u32 options_len = tcp_header_len - sizeof(struct tcphdr_min);
        if (options_len > 0 && options_len <= 40) {
            __u32 opt_offset = tcp_offset + sizeof(struct tcphdr_min);
            __u8 *opt_ptr = data + opt_offset;
            #pragma unroll
            for (__u32 i = 0; i < 40; i++) {
                if (i >= options_len) break;
                __u8 *current_opt = opt_ptr + i;
                if ((void *)(current_opt + 1) > data_end) break;
                __u8 opt_kind = *current_opt;
                if (opt_kind == TCPOPT_EOL) break;
                if (opt_kind == TCPOPT_NOP) continue;
                if ((void *)(current_opt + 2) > data_end) break;
                __u8 opt_len = *(current_opt + 1);
                if (opt_len < 2 || opt_len > 40) break;
                if (i + opt_len > options_len) break;

                /* Apply configurable MSS */
                if (opt_kind == TCPOPT_MSS && opt_len == 4) {
                    if ((void *)(current_opt + 4) > data_end) break;
                    __u16 new_mss = cfg->mss;
                    __be16 new_mss_be = bpf_htons(new_mss);
                    __u32 mss_offset = opt_offset + i + 2;
                    bpf_skb_store_bytes(skb, mss_offset, &new_mss_be, 2, 0);

                    data = (void *)(long)skb->data;
                    data_end = (void *)(long)skb->data_end;
                    opt_ptr = data + opt_offset;
                }

                /* Apply configurable window scale */
                if (opt_kind == TCPOPT_WINDOW_SCALE && opt_len == 3) {
                    if ((void *)(current_opt + 3) > data_end) break;
                    __u8 old_wscale = *(current_opt + 2);
                    __u8 new_wscale = cfg->window_scale;
                    if (old_wscale != new_wscale) {
                        __u32 wscale_offset = opt_offset + i + 2;
                        bpf_skb_store_bytes(skb, wscale_offset, &new_wscale, 1, 0);

                        data = (void *)(long)skb->data;
                        data_end = (void *)(long)skb->data_end;
                        opt_ptr = data + opt_offset;
                    }
                }

                /*
                 * Handle TCP Timestamps based on OS profile:
                 * - Windows: timestamps_enabled=0 (do not modify, let OS behavior through)
                 * - Linux/macOS: timestamps_enabled=1 (randomize timestamp value)
                 *
                 * Note: For Windows fingerprint, ideally we would strip the timestamp
                 * option entirely, but that requires packet size modification which is
                 * complex in eBPF. Current approach: only randomize if enabled.
                 */
                if (opt_kind == TCPOPT_TIMESTAMP && opt_len == 10 && cfg->timestamps_enabled) {
                    if ((void *)(current_opt + 10) > data_end) break;
                    __u64 timestamp = bpf_ktime_get_ns();
                    __u32 new_tsval = (__u32)(timestamp >> 10);
                    __be32 new_tsval_be = bpf_htonl(new_tsval);
                    __u32 tsval_offset = opt_offset + i + 2;
                    bpf_skb_store_bytes(skb, tsval_offset, &new_tsval_be, 4, 0);

                    data = (void *)(long)skb->data;
                    data_end = (void *)(long)skb->data_end;
                    opt_ptr = data + opt_offset;
                }
                i += opt_len - 1;
            }
        }
    }

}

char LICENSE[] SEC("license") = "GPL";