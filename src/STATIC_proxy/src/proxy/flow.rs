/* STATIC Proxy (AGPL-3.0)

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

use crate::behavior::BehavioralNoisePlan;
use bytes::BytesMut;
use http::{header::HeaderName, HeaderMap, Method, Uri, Version};
use serde_json::Value;
use uuid::Uuid;

/// Flow tracks everything we know about a single HTTP request/response pair as it moves
/// through the STATIC pipeline. Each HTTP/1.1 request or HTTP/2 stream gets its own Flow
/// so stages can mutate headers, bodies, and metadata without touching other traffic.
///
/// A Flow is created immediately after the TLS handshake, populated with the parsed
/// request, run through the stage pipeline, forwarded upstream, and finally logged once
/// the downstream response is delivered. Flows are owned by a single task, so mutating
/// them with `&mut` is safe without extra synchronization.
#[derive(Debug)]
pub struct Flow {
    /// Unique identifier for this request/response pair (UUID v7 = timestamp-sortable).
    /// Used for tracing, logging, and correlating telemetry events.
    pub id: Uuid,

    /// Parsed HTTP request from the client (method, URI, headers, body).
    pub request: RequestParts,

    /// Parsed HTTP response from upstream (status, headers, body).
    /// None until the upstream response arrives (or if the request fails before reaching upstream).
    pub response: Option<ResponseParts>,

    /// Cross-stage metadata scratchpad (TLS SNI, profile selection, CSP nonces, etc.).
    /// Stages write to this to communicate with each other and with telemetry.
    pub metadata: FlowMetadata,
}

impl Flow {
    /// Creates a new Flow for the given request.
    ///
    /// **UUID v7:**
    /// Uuid::now_v7() generates a time-ordered UUID (sortable by creation time), which is
    /// useful for tracing and log correlation. Unlike v4 (random), v7 UUIDs reveal rough
    /// temporal ordering without needing a separate timestamp field.
    pub fn new(request: RequestParts) -> Self {
        Self {
            id: Uuid::now_v7(),
            request,
            response: None,
            metadata: FlowMetadata::default(),
        }
    }
}

/// Parsed HTTP request components (method, URI, version, headers, body).
///
/// **Purpose:**
/// Provides a mutable, owned representation of the client's HTTP request that pipeline
/// stages can inspect and modify. Mirrors hyper's Request type but with owned data for
/// easier mutation across async stage boundaries.
///
/// We keep an owned version of the HTTP request rather than hyper's streaming `Body` so
/// stages can edit data without juggling lifetimes or async readers. Parsing already
/// fills these fields with the real method, URI, headers, and buffered body.
#[derive(Debug)]
pub struct RequestParts {

    pub method: Method,

    pub uri: Uri,

    pub version: Version,

    pub headers: HeaderMap,

    pub body: BodyBuffer,
}

impl Default for RequestParts {
    /// Placeholder request for testing/development before HTTP parsing lands.
    fn default() -> Self {
        Self {
            method: Method::GET,
            uri: Uri::from_static("http://example"),
            version: Version::HTTP_11,
            headers: HeaderMap::new(),
            body: BodyBuffer::default(),
        }
    }
}

/// Parsed HTTP response components (status, version, headers, body).
#[derive(Debug, Default)]
pub struct ResponseParts {

    pub status: http::StatusCode,
    
    pub version: Version,
   
    pub headers: HeaderMap,

    pub body: BodyBuffer,
}

/// Growable byte buffer for HTTP request/response bodies.
///
/// Bodies are currently fully buffered in memory via `BytesMut`, which keeps stage logic
/// simple (no streaming state machines) at the cost of higher memory usage on very large
/// payloads. We can revisit this once streaming transformations land.
#[derive(Debug, Default)]
pub struct BodyBuffer {
    /// Internal buffer using BytesMut for efficient growth.
    /// BytesMut pre-allocates capacity and uses copy-on-write for slicing.
    data: BytesMut,
}

impl BodyBuffer {
    /// Appends a byte slice to the buffer. BytesMut handles growth internally so most
    /// appends are a memcpy against pre-allocated capacity.
    pub fn push_bytes(&mut self, chunk: &[u8]) {
        self.data.extend_from_slice(chunk);
    }

    /// Returns a read-only view of the buffered data so stages can inspect payloads.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Returns the number of bytes currently buffered.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Replaces the buffer with new contents.
    pub fn replace(&mut self, chunk: &[u8]) {
        self.data.clear();
        self.data.extend_from_slice(chunk);
    }

    /// Returns true when no bytes are buffered.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// FlowMetadata is a typed scratchpad for stages to communicate (CSP nonce handoffs,
/// profile selections, protocol labels) and for telemetry to record the final state of
/// the flow without poking at stage internals.
#[derive(Debug, Default)]
pub struct FlowMetadata {

    pub tls_sni: Option<String>,

    pub connect_target: Option<String>,

    pub profile_name: Option<String>,

    pub browser_profile: Option<String>,

    pub user_agent: Option<String>,

    pub fingerprint_config: Value,

    pub csp_nonce: Option<String>,

    pub script_hashes: Vec<String>,

    pub alt_svc_mutations: Vec<String>,

    /// Registrable domain (eTLD+1) of the top-level site for this flow, used for cookie partitioning.
    pub top_site: Option<String>,

    
    pub client_protocol: Option<String>,

    
    pub upstream_protocol: Option<String>,

    
    pub behavioral_noise: BehavioralNoiseMetadata,

    pub original_csp_headers: Option<Vec<(HeaderName, Vec<String>)>>,

    /// Packet header context for HTTP header ordering and TCP fingerprint coordination.
    pub packet_headers: PacketHeaderContext,
}

#[derive(Debug, Default)]
pub struct BehavioralNoiseMetadata {

    pub enabled: bool,

    pub plan: Option<BehavioralNoisePlan>,

    pub engine_tag: Option<String>,

    pub markers: Vec<String>,
}

/// PacketHeaderContext tracks header ordering and TCP fingerprint metadata for stealth evasion.
/// This enables the proxy to reorder HTTP headers to match real browser fingerprints and
/// coordinate TCP-level fingerprint spoofing with the eBPF module.
///
/// # Fingerprint Evasion Architecture
///
/// Modern fingerprinting services detect proxies/bots by analyzing patterns that differ from
/// real browser behavior. This includes:
///
/// 1. **HTTP Header Ordering**: Browsers send headers in a consistent, browser-specific order.
///    Chrome, Firefox, and Edge each have distinct ordering patterns. Proxies that don't
///    preserve or emulate these patterns are easily detected.
///
/// 2. **Header Capitalization (HTTP/1.1)**: While HTTP headers are case-insensitive per spec,
///    real browsers use consistent capitalization (e.g., "User-Agent" not "user-agent").
///    Some fingerprinting services check this.
///
/// 3. **HTTP/2 Pseudo-Header Order**: The order of pseudo-headers (:method, :authority, etc.)
///    in HTTP/2 HEADERS frames varies by browser. Chrome typically sends :method first,
///    while Firefox has different patterns.
///
/// 4. **TCP/IP Fingerprinting**: OS-level network stack characteristics (TTL, MSS, window
///    size, TCP options order) reveal the underlying operating system. A "Windows Chrome"
///    user-agent with Linux TCP characteristics is suspicious.
///
/// # Coordination with eBPF
///
/// The `tcp_fingerprint` field contains hints that can be passed to the eBPF module
/// (`ttl_editor.c`) via the `fingerprint_settings` BPF map. This enables userspace-to-kernel
/// coordination for consistent fingerprint spoofing across all network layers.
///
/// # Usage
///
/// This context is populated by `PacketHeaderStage` during request processing. The stage
/// reads configuration from the browser profile JSON and applies appropriate transformations.
/// Telemetry markers track what modifications were made for debugging/logging.
///
/// # Example Profile Configuration
///
/// ```json
/// {
///   "packet_headers": {
///     "header_order": ["host", "connection", "user-agent", ...],
///     "h2_pseudo_order": [":method", ":authority", ":scheme", ":path"],
///     "header_case": {"host": "Host", "user-agent": "User-Agent"}
///   },
///   "tcp_fingerprint": {
///     "target_os": "windows",
///     "ttl": 128,
///     "mss": 1460,
///     "window_size": 65535,
///     "timestamps_enabled": false
///   }
/// }
/// ```
#[derive(Debug, Default, Clone)]
pub struct PacketHeaderContext {
    /// Whether packet header processing is enabled for this flow.
    /// When false, headers pass through unmodified (useful for debugging or bypass).
    pub enabled: bool,

    /// Original header names in the order they were received from the client.
    /// Captured before any reordering for telemetry comparison and debugging.
    /// Example: ["accept-encoding", "user-agent", "host", "accept"]
    pub original_header_order: Vec<String>,

    /// Header names in the order they will be sent upstream (after reordering).
    /// Matches the target browser's header ordering pattern.
    /// Example (Chrome): ["host", "connection", "user-agent", "accept", "accept-encoding"]
    pub applied_header_order: Vec<String>,

    /// Mapping of lowercase header names to their properly-cased forms.
    /// Used for HTTP/1.1 where header case is preserved on the wire.
    /// HTTP/2 always lowercases headers, so this only affects HTTP/1.1 connections.
    ///
    /// Example: {"user-agent" -> "User-Agent", "accept-encoding" -> "Accept-Encoding"}
    ///
    /// Note: The http crate normalizes headers internally; this map is for serialization.
    pub header_case_map: std::collections::HashMap<String, String>,

    /// Deterministic fingerprint ID derived from flow ID using a simple hash.
    /// Provides consistent per-session identification without being predictable.
    /// Format: "pkt-{16 hex chars}" (e.g., "pkt-a1b2c3d4e5f67890")
    pub packet_fingerprint_id: String,

    /// HTTP/2 pseudo-header ordering to apply when sending HEADERS frames.
    /// Different browsers have different preferred orders:
    /// - Chrome: [":method", ":authority", ":scheme", ":path"]
    /// - Firefox: [":method", ":path", ":authority", ":scheme"]
    ///
    /// This field stores the target order from the profile.
    pub h2_pseudo_order: Vec<String>,

    /// TCP fingerprint hints for coordination with the eBPF kernel module.
    /// Contains OS-specific network stack characteristics (TTL, MSS, window size, etc.)
    /// that the eBPF module uses to modify outgoing packets at the kernel level.
    pub tcp_fingerprint: TcpFingerprintHints,

    /// Markers for telemetry and debugging, tracking what modifications were made.
    /// Examples:
    /// - "headers_reordered": Header order was changed from original
    /// - "tcp_target_os:windows": TCP fingerprint set to Windows profile
    /// - "tcp_ttl:128": Specific TTL value being used
    /// - "response_headers_processed": Response headers were also processed
    pub markers: Vec<String>,
}

/// TCP fingerprint configuration hints coordinated between Rust proxy and eBPF module.
/// These values can be set per-profile to match specific OS/browser combinations.
///
/// # TCP/IP Fingerprinting Background
///
/// Every operating system implements the TCP/IP stack with subtle differences that can be
/// detected remotely. Fingerprinting tools like p0f, Nmap, and commercial services analyze:
///
/// - **IP TTL (Time To Live)**: Initial TTL value varies by OS. Windows uses 128, while
///   Linux and macOS use 64. After traversing N hops, received TTL reveals original value.
///
/// - **TCP Window Size**: Initial window size and scaling behavior differs. Windows 10+
///   typically uses 65535, Linux varies by kernel version and sysctl settings.
///
/// - **TCP Options Order**: The ORDER of TCP options in SYN packets is OS-specific and
///   one of the most reliable fingerprinting signals. Windows, Linux, and macOS each
///   have distinct ordering patterns.
///
/// - **TCP Timestamps**: Windows disables TCP timestamps by default, while Unix systems
///   enable them. Presence/absence of timestamp option is a strong signal.
///
/// # eBPF Integration
///
/// These hints are passed to the eBPF module (`ttl_editor.c`) via a BPF map. The kernel
/// module modifies outgoing packets at the TC (Traffic Control) layer before they leave
/// the network interface. This enables spoofing of TCP/IP characteristics that would
/// otherwise be determined by the host OS.
///
/// To apply these settings, userspace code should:
/// 1. Open the `fingerprint_settings` BPF map
/// 2. Serialize this struct into a `fingerprint_config` C struct
/// 3. Write to key 0 in the map using `bpf_map_update_elem()`
///
/// # OS Fingerprint Profiles
///
/// ## Windows 10/11 (Chrome/Edge)
/// ```text
/// TTL: 128
/// Window: 65535
/// Scale: 8
/// Options: MSS, NOP, WS, NOP, NOP, SACK_PERM
/// Timestamps: disabled
/// DF: 1 (Don't Fragment set)
/// ```
///
/// ## Linux (Firefox/Chrome)
/// ```text
/// TTL: 64
/// Window: varies (29200 common)
/// Scale: 7
/// Options: MSS, SACK_PERM, TS, NOP, WS
/// Timestamps: enabled
/// DF: 1
/// ```
///
/// ## macOS (Safari/Chrome)
/// ```text
/// TTL: 64
/// Window: 65535
/// Scale: 6
/// Options: MSS, NOP, WS, NOP, NOP, TS, SACK_PERM, EOL
/// Timestamps: enabled
/// DF: 1
/// ```
///
/// # Security Considerations
///
/// TCP fingerprint spoofing is detectable if:
/// - HTTP User-Agent claims different OS than TCP fingerprint (correlation attack)
/// - TLS fingerprint (JA3/JA4) doesn't match claimed browser
/// - Other timing/behavioral characteristics don't match
///
/// For maximum stealth, ensure consistency across all layers: HTTP headers, TLS,
/// TCP/IP, and behavioral patterns (request timing, mouse movements, etc.)
#[derive(Debug, Clone)]
pub struct TcpFingerprintHints {
    /// Target OS for TCP fingerprinting.
    /// Valid values: "windows", "linux", "macos", "custom"
    /// Used for logging and to infer defaults if other fields aren't specified.
    pub target_os: String,

    /// IP Time-To-Live value (8-bit field, max 255).
    /// This is the initial TTL set on outgoing packets.
    /// - Windows: 128 (packets appear as ~120 TTL after typical hop count)
    /// - Linux/macOS: 64 (packets appear as ~50-60 TTL after typical hop count)
    ///
    /// Modified by eBPF at egress; doesn't affect routing decisions.
    pub ttl: u8,

    /// TCP Maximum Segment Size (MSS) advertised in SYN packets.
    /// Standard value: 1460 for Ethernet MTU 1500 (1500 - 20 IP - 20 TCP = 1460)
    ///
    /// Some VPNs/tunnels use smaller values (1400, 1380) which can be fingerprinted.
    /// For stealth, use 1460 unless you need to account for encapsulation overhead.
    pub mss: u16,

    /// TCP Window Size advertised in SYN packets.
    /// Represents the receive buffer size in bytes.
    /// - Windows: 65535 (common default)
    /// - Linux: Varies by kernel (29200, 65535, or calculated from buffer settings)
    /// - macOS: 65535
    ///
    /// Combined with window_scale, determines effective window (window_size << scale).
    pub window_size: u16,

    /// TCP Window Scale factor (RFC 7323), allows windows > 64KB.
    /// Sent as TCP option in SYN. Actual window = window_size << window_scale.
    /// - Windows 10+: 8 (effective max window ~16MB)
    /// - Linux: 5-7 depending on kernel/sysctl
    /// - macOS: 6
    pub window_scale: u8,

    /// Whether TCP timestamps (RFC 7323) should be included in packets.
    /// - Windows: false (timestamps disabled by default, strong fingerprint signal!)
    /// - Linux: true (timestamps enabled by default)
    /// - macOS: true
    ///
    /// Note: eBPF can randomize timestamp values but cannot add/remove the option
    /// without complex packet reconstruction. For Windows spoofing, ensure the
    /// host OS is configured to disable timestamps or accept detection risk.
    pub timestamps_enabled: bool,

    /// TCP options order for SYN packets - one of the strongest fingerprint signals.
    /// Options are: "MSS", "NOP", "WS", "SACK_PERM", "TS", "EOL"
    ///
    /// Each OS orders these differently:
    /// - Windows: ["MSS", "NOP", "WS", "NOP", "NOP", "SACK_PERM"]
    /// - Linux:   ["MSS", "SACK_PERM", "TS", "NOP", "WS"]
    /// - macOS:   ["MSS", "NOP", "WS", "NOP", "NOP", "TS", "SACK_PERM", "EOL"]
    ///
    /// Note: Full reordering requires packet reconstruction. The eBPF module currently
    /// modifies option VALUES in place. For complete stealth, consider implementing
    /// options reordering via raw sockets or nftables packet mangling.
    pub tcp_options_order: Vec<String>,

    /// IP Don't Fragment (DF) flag in IP header.
    /// - true: DF=1, packet should not be fragmented (most modern OS default)
    /// - false: DF=0, packet may be fragmented
    ///
    /// Almost all modern systems set DF=1 for Path MTU Discovery.
    /// DF=0 is rare and may indicate unusual/legacy systems.
    pub df_flag: bool,

    /// IP Type of Service (ToS) / Differentiated Services Code Point (DSCP) field.
    /// 8-bit field in IP header for QoS marking.
    /// - 0x00: Best effort (default for most traffic)
    /// - Other values indicate specific QoS requirements
    ///
    /// Most browsers use 0x00. Non-zero values may be fingerprinted.
    pub ip_tos: u8,

    /// Whether to randomize the IP Identification field.
    /// IP ID is a 16-bit field used for fragment reassembly.
    /// - true: Randomize to prevent tracking/fingerprinting via ID sequence
    /// - false: Use kernel's default (often sequential, enabling tracking)
    ///
    /// Modern recommendation is true to prevent IP ID-based tracking attacks.
    pub randomize_ip_id: bool,

    /// Whether to randomize TCP Initial Sequence Number (ISN).
    /// ISN is the first sequence number in a TCP connection.
    /// - true: Use cryptographically random ISN (security best practice)
    /// - false: Use deterministic/predictable ISN (legacy, insecure)
    ///
    /// All modern OS randomize ISN. This should generally be true.
    /// Set false only for specific compatibility testing scenarios.
    pub randomize_seq: bool,
}

impl Default for TcpFingerprintHints {
    /// Creates default TCP fingerprint hints matching a Windows 10/11 system.
    ///
    /// Windows is chosen as the default because:
    /// 1. Chrome and Edge on Windows are the most common browser configurations
    /// 2. Windows has distinct characteristics (TTL=128, no timestamps) that differ
    ///    from server environments (Linux TTL=64, timestamps enabled)
    /// 3. Most fingerprinting services expect Windows for desktop browser traffic
    ///
    /// To emulate Linux or macOS, either:
    /// - Set profile JSON with explicit `tcp_fingerprint` section, or
    /// - Set `fingerprint.os` to "linux" or "macos" for automatic inference
    fn default() -> Self {
        Self {
            target_os: "windows".to_string(),
            ttl: 128,                      // Windows default TTL
            mss: 1460,                     // Standard Ethernet MSS
            window_size: 65535,            // Windows default (max without scaling)
            window_scale: 8,               // Windows 10+ default
            timestamps_enabled: false,      // Windows disables by default!
            tcp_options_order: vec![       // Windows SYN option order
                "MSS".to_string(),
                "NOP".to_string(),
                "WS".to_string(),
                "NOP".to_string(),
                "NOP".to_string(),
                "SACK_PERM".to_string(),
            ],
            df_flag: true,                 // Don't Fragment (standard)
            ip_tos: 0x00,                  // Best effort QoS
            randomize_ip_id: true,         // Privacy: prevent IP ID tracking
            randomize_seq: true,           // Security: unpredictable ISN
        }
    }
}
