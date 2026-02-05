/* TCP/IP Fingerprint Editor - Configurable Packet Header Engine
 *
 * Copyright (C) 2025 - 404 Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * ===========================================================================
 *
 * OVERVIEW
 * --------
 * This eBPF program provides kernel-level TCP/IP fingerprint spoofing for the
 * 404 proxy. It modifies outgoing packets at the TC (Traffic Control) egress
 * hook to change OS-identifiable characteristics before packets leave the
 * network interface.
 *
 * WHY EBPF FOR FINGERPRINT SPOOFING?
 * ----------------------------------
 * TCP/IP fingerprinting tools (p0f, Nmap, commercial services) identify the
 * operating system by analyzing packet characteristics that are set by the
 * kernel network stack, NOT by userspace applications. Even if your HTTP
 * headers claim to be "Chrome on Windows", if your packets have Linux TCP
 * characteristics (TTL=64, specific TCP options order), you're detected.
 *
 * eBPF allows us to modify packets AFTER the kernel has constructed them
 * but BEFORE they leave the network interface. This is the only reliable
 * way to spoof TCP/IP fingerprints without modifying the kernel itself.
 *
 * WHAT THIS MODULE MODIFIES
 * -------------------------
 *
 * IPv4 Packets:
 *   - TTL (Time To Live): Windows=128, Linux/macOS=64
 *   - IP ID: Randomized to prevent tracking via sequential IDs
 *   - ToS/DSCP: Set to match target OS (usually 0x00)
 *
 * IPv6 Packets:
 *   - Hop Limit: Same as TTL (Windows=128, Linux/macOS=64)
 *   - Flow Label: Randomized for privacy
 *
 * TCP Packets (especially SYN):
 *   - Window Size: OS-specific initial window (Windows=65535)
 *   - Initial Sequence Number: Randomized for security
 *   - MSS (Maximum Segment Size): Usually 1460 for Ethernet
 *   - Window Scale: OS-specific (Windows=8, Linux=7, macOS=6)
 *   - Timestamps: Randomized if enabled (Windows disables by default)
 *
 * CONFIGURATION VIA BPF MAP
 * -------------------------
 * Instead of compile-time constants, this module reads configuration from
 * the `fingerprint_settings` BPF map. Userspace can update the map to change
 * fingerprint characteristics without reloading the eBPF program.
 *
 * To update settings from userspace (using libbpf):
 *
 *   struct fingerprint_config cfg = {
 *       .os_profile = 0,        // Windows
 *       .ttl = 128,
 *       .hop_limit = 128,
 *       .mss = 1460,
 *       .window_size = 65535,
 *       .window_scale = 8,
 *       .timestamps_enabled = 0,
 *       // ... etc
 *   };
 *   __u32 key = 0;
 *   bpf_map_update_elem(map_fd, &key, &cfg, BPF_ANY);
 *
 * COORDINATION WITH RUST PROXY
 * ----------------------------
 * The Rust STATIC proxy's PacketHeaderStage extracts TCP fingerprint hints
 * from browser profiles and stores them in flow.metadata.packet_headers.tcp_fingerprint.
 * A separate component (not yet implemented) should:
 *
 *   1. Watch for profile changes in the proxy
 *   2. Convert TcpFingerprintHints to fingerprint_config struct
 *   3. Update the fingerprint_settings BPF map
 *
 * This enables per-profile TCP fingerprint spoofing coordinated with HTTP
 * header spoofing for complete fingerprint consistency.
 *
 * LIMITATIONS
 * -----------
 * 1. TCP Options Reordering: This module can modify option VALUES but cannot
 *    easily reorder options in the packet (would require packet reconstruction).
 *    For complete stealth, consider raw sockets or nftables for options reordering.
 *
 * 2. Timestamp Removal: Windows doesn't send TCP timestamps by default. We can
 *    randomize timestamps but cannot remove the option without complex surgery.
 *    Ensure host OS is configured appropriately for full Windows emulation.
 *
 * 3. Checksum Recalculation: After modifying IP headers, we recalculate the IP
 *    checksum. TCP checksum is NOT recalculated (left to hardware offload).
 *    Verify with packet captures that checksums are correct.
 *
 * SECURITY CONSIDERATIONS
 * -----------------------
 * - Fingerprint spoofing can be detected through correlation attacks (HTTP
 *   headers vs TCP fingerprint vs TLS fingerprint)
 * - Timing analysis may reveal proxy presence
 * - Some advanced fingerprinting uses multiple packets to verify consistency
 *
 * This module is part of a defense-in-depth approach. Use alongside HTTP header
 * spoofing, TLS fingerprint spoofing, and behavioral noise for best results.
 *
 * ===========================================================================
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
 * --------------------------------------------------------
 *
 * This structure is stored in a BPF map and can be updated from userspace
 * to dynamically change fingerprint characteristics per OS profile.
 *
 * OS Profiles (os_profile field):
 *   0 = Windows (TTL=128, no timestamps, MSS-NOP-WS-NOP-NOP-SACK)
 *   1 = Linux   (TTL=64, timestamps, MSS-SACK-TS-NOP-WS)
 *   2 = macOS   (TTL=64, timestamps, MSS-NOP-WS-NOP-NOP-TS-SACK-EOL)
 *   3 = Custom  (user-defined values, all fields respected)
 *
 * Structure Layout:
 *   The struct is __attribute__((packed)) to ensure predictable memory layout
 *   across architectures. Total size: 16 bytes.
 *
 * Usage from Rust:
 *   This struct corresponds to TcpFingerprintHints in flow.rs. When updating
 *   the BPF map, convert TcpFingerprintHints to this C struct format.
 *
 *   Example mapping:
 *     TcpFingerprintHints.ttl         -> fingerprint_config.ttl
 *     TcpFingerprintHints.mss         -> fingerprint_config.mss
 *     TcpFingerprintHints.window_size -> fingerprint_config.window_size
 *     etc.
 *
 * Typical Configurations:
 *
 *   Windows 10/11:
 *     { .os_profile=0, .ttl=128, .hop_limit=128, .ip_tos=0, .mss=1460,
 *       .window_size=65535, .window_scale=8, .timestamps_enabled=0,
 *       .randomize_ip_id=1, .randomize_seq=1, .randomize_ipv6_flow=1,
 *       .df_flag=1 }
 *
 *   Linux (Ubuntu 22.04 / kernel 5.x):
 *     { .os_profile=1, .ttl=64, .hop_limit=64, .ip_tos=0, .mss=1460,
 *       .window_size=65535, .window_scale=7, .timestamps_enabled=1,
 *       .randomize_ip_id=1, .randomize_seq=1, .randomize_ipv6_flow=1,
 *       .df_flag=1 }
 *
 *   macOS (Ventura/Sonoma):
 *     { .os_profile=2, .ttl=64, .hop_limit=64, .ip_tos=0, .mss=1460,
 *       .window_size=65535, .window_scale=6, .timestamps_enabled=1,
 *       .randomize_ip_id=1, .randomize_seq=1, .randomize_ipv6_flow=1,
 *       .df_flag=1 }
 */
struct fingerprint_config {
    __u8  os_profile;           /* OS profile identifier: 0=Windows, 1=Linux, 2=macOS, 3=Custom
                                 * Used for logging/debugging; actual values come from fields below */
    __u8  ttl;                  /* IPv4 Time-To-Live (8-bit, max 255)
                                 * Windows=128, Linux/macOS=64
                                 * After ~10-15 hops, received TTL reveals original value */
    __u8  hop_limit;            /* IPv6 Hop Limit (equivalent to TTL for IPv6)
                                 * Should match ttl for consistency */
    __u8  ip_tos;               /* IP Type of Service / DSCP field
                                 * 0x00 = Best effort (default for browsers)
                                 * Non-zero values may be fingerprinted */
    __u16 mss;                  /* TCP Maximum Segment Size (16-bit)
                                 * 1460 = standard for Ethernet MTU 1500
                                 * VPN/tunnels may use smaller (1400, 1380) */
    __u16 window_size;          /* TCP Window Size (16-bit)
                                 * 65535 = common Windows/macOS default
                                 * Combined with window_scale for effective window */
    __u8  window_scale;         /* TCP Window Scale factor (0-14)
                                 * Effective window = window_size << window_scale
                                 * Windows=8, Linux=7, macOS=6 */
    __u8  timestamps_enabled;   /* Whether to process TCP timestamps
                                 * 0 = Don't modify (Windows default = disabled)
                                 * 1 = Randomize timestamp values (Unix default = enabled)
                                 * NOTE: Cannot add/remove option, only modify value */
    __u8  randomize_ip_id;      /* Randomize IPv4 ID field
                                 * 1 = randomize to prevent tracking
                                 * 0 = use kernel default (may be sequential) */
    __u8  randomize_seq;        /* Randomize TCP Initial Sequence Number
                                 * 1 = use random ISN (security best practice)
                                 * 0 = use deterministic ISN (legacy, insecure) */
    __u8  randomize_ipv6_flow;  /* Randomize IPv6 Flow Label
                                 * 1 = randomize 20-bit flow label
                                 * 0 = preserve original */
    __u8  df_flag;              /* IPv4 Don't Fragment flag
                                 * 1 = set DF (standard for Path MTU Discovery)
                                 * 0 = clear DF (unusual, may be fingerprinted) */
    __u8  reserved[2];          /* Padding for 4-byte alignment
                                 * Future expansion possible */
} __attribute__((packed));      /* Ensure no compiler padding between fields */

/*
 * BPF Map: protocol_counter
 * -------------------------
 * Telemetry map for counting packets by IP protocol number.
 * Used for debugging and monitoring traffic patterns.
 *
 * Key:   Protocol number (0-255) from IP header
 *        Common values: 6=TCP, 17=UDP, 1=ICMP, 58=ICMPv6
 * Value: Packet count (atomically incremented)
 *
 * Access from userspace:
 *   long count;
 *   __u32 tcp_key = 6;
 *   bpf_map_lookup_elem(map_fd, &tcp_key, &count);
 *   printf("TCP packets processed: %ld\n", count);
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);      /* One slot per protocol number (0-255) */
    __type(key, __u32);
    __type(value, long);
} protocol_counter SEC(".maps");

/*
 * BPF Map: fingerprint_settings
 * -----------------------------
 * Runtime configuration map for TCP/IP fingerprint spoofing.
 * Updated from userspace to change OS fingerprint profile.
 *
 * Key:   Always 0 (single-entry array)
 * Value: struct fingerprint_config with all fingerprint parameters
 *
 * This map enables dynamic fingerprint switching without reloading
 * the eBPF program. The Rust proxy can update this map when:
 *   - Browser profile changes
 *   - User requests different OS fingerprint
 *   - Per-destination fingerprint rules apply
 *
 * Update from userspace (using libbpf):
 *   int map_fd = bpf_obj_get("/sys/fs/bpf/fingerprint_settings");
 *   struct fingerprint_config cfg = { ... };
 *   __u32 key = 0;
 *   bpf_map_update_elem(map_fd, &key, &cfg, BPF_ANY);
 *
 * If the map is empty (not yet populated), get_fingerprint_config()
 * returns Windows defaults for compatibility.
 *
 * Coordination with Rust Proxy:
 *   The TcpFingerprintHints struct in flow.rs mirrors this config.
 *   A userspace component should:
 *     1. Read flow.metadata.packet_headers.tcp_fingerprint
 *     2. Convert to fingerprint_config struct
 *     3. Write to this map via bpf_map_update_elem()
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);        /* Single configuration slot */
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

/*
 * get_fingerprint_config - Retrieve current fingerprint configuration
 * -------------------------------------------------------------------
 *
 * Looks up the fingerprint_settings BPF map to get the active configuration.
 * If the map hasn't been populated by userspace, returns Windows defaults.
 *
 * Why Windows Defaults?
 *   - Chrome on Windows is the most common browser configuration
 *   - Windows characteristics (TTL=128, no timestamps) differ clearly from
 *     server environments (Linux TTL=64, timestamps enabled)
 *   - Most fingerprinting services expect Windows for desktop browser traffic
 *   - Safe default that won't cause obvious detection for typical use cases
 *
 * Note on __always_inline:
 *   eBPF has strict constraints on function calls. __always_inline ensures
 *   this function is inlined at every call site, avoiding BPF verifier issues
 *   with function calls in older kernels.
 *
 * Returns:
 *   struct fingerprint_config with either map values or Windows defaults
 */
static __always_inline struct fingerprint_config get_fingerprint_config(void)
{
    __u32 key = 0;
    struct fingerprint_config *cfg = bpf_map_lookup_elem(&fingerprint_settings, &key);

    /* If map lookup succeeds, use the configured values */
    if (cfg) {
        return *cfg;
    }

    /* Map empty or lookup failed - return Windows defaults
     * This is the safest default for typical browser spoofing scenarios */
    struct fingerprint_config defaults = {
        .os_profile = 0,                    /* Windows profile */
        .ttl = DEFAULT_TTL,                 /* 128 - Windows TTL */
        .hop_limit = DEFAULT_TTL,           /* 128 - IPv6 hop limit matches TTL */
        .ip_tos = DEFAULT_IP_TOS,           /* 0x00 - best effort */
        .mss = DEFAULT_TCP_MSS,             /* 1460 - standard Ethernet */
        .window_size = DEFAULT_TCP_WINDOW_SIZE, /* 65535 - Windows default */
        .window_scale = DEFAULT_TCP_WINDOW_SCALE, /* 8 - Windows 10+ */
        .timestamps_enabled = 0,            /* Windows disables timestamps! */
        .randomize_ip_id = 1,               /* Privacy: prevent IP ID tracking */
        .randomize_seq = 1,                 /* Security: unpredictable ISN */
        .randomize_ipv6_flow = 1,           /* Privacy: randomize flow label */
        .df_flag = 1,                       /* Windows sets Don't Fragment */
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