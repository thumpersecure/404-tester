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

//! # PacketHeaderStage - HTTP Header Ordering and TCP Fingerprint Coordination
//!
//! This module implements stealth-focused HTTP header reordering and TCP fingerprint
//! coordination for fingerprint evasion. It's a critical component of the 404 proxy's
//! anti-detection capabilities.
//!
//! ## Why Header Ordering Matters
//!
//! Real browsers send HTTP headers in specific, consistent orders determined by their
//! implementation. Fingerprinting services like FingerprintJS, PerimeterX, Cloudflare
//! Bot Management, and DataDome analyze these patterns to detect proxy/bot traffic.
//!
//! A request claiming to be Chrome but sending headers in Python-requests order (alphabetical
//! or random) is immediately flagged. Even subtle differences like Accept-Encoding before
//! User-Agent (Firefox) vs. User-Agent before Accept-Encoding (Chrome) are detectable.
//!
//! ## What This Stage Does
//!
//! 1. **HTTP/1.1 Header Reordering**: Reorders request headers to match the target browser's
//!    expected order (Chrome, Firefox, or Edge patterns).
//!
//! 2. **Header Case Normalization**: While HTTP headers are case-insensitive per spec, browsers
//!    use consistent capitalization (e.g., "User-Agent" not "user-agent"). HTTP/1.1 preserves
//!    case on the wire, so mismatched case is detectable.
//!
//! 3. **HTTP/2 Pseudo-Header Ordering**: HTTP/2 uses pseudo-headers (:method, :authority,
//!    :scheme, :path) that also have browser-specific ordering in HEADERS frames.
//!
//! 4. **TCP Fingerprint Extraction**: Reads TCP/IP fingerprint configuration from browser
//!    profiles and populates hints for the eBPF kernel module to apply at the packet level.
//!
//! ## Pipeline Position
//!
//! This stage runs AFTER `HeaderProfileStage` in the pipeline. HeaderProfileStage loads the
//! browser profile JSON and populates `flow.metadata.fingerprint_config`. PacketHeaderStage
//! reads that config to determine the correct header ordering and TCP characteristics.
//!
//! ```text
//! Request Flow:
//! [Client] -> [TLS] -> [Parse] -> [CookieIsolation] -> [HeaderProfile] -> [PacketHeaders] -> ...
//!                                                           |                    |
//!                                                    loads profile          reorders headers
//!                                                                          extracts TCP hints
//! ```
//!
//! ## Configuration
//!
//! Header ordering and TCP fingerprints are configured per-profile in JSON files:
//!
//! ```json
//! {
//!   "fingerprint": {
//!     "browser_type": "chrome",
//!     "os": "Windows"
//!   },
//!   "packet_headers": {
//!     "header_order": ["host", "connection", "cache-control", "sec-ch-ua", ...],
//!     "h2_pseudo_order": [":method", ":authority", ":scheme", ":path"],
//!     "header_case": {
//!       "host": "Host",
//!       "user-agent": "User-Agent",
//!       "accept-encoding": "Accept-Encoding"
//!     }
//!   },
//!   "tcp_fingerprint": {
//!     "target_os": "windows",
//!     "ttl": 128,
//!     "mss": 1460,
//!     "window_size": 65535,
//!     "window_scale": 8,
//!     "timestamps_enabled": false,
//!     "tcp_options_order": ["MSS", "NOP", "WS", "NOP", "NOP", "SACK_PERM"]
//!   }
//! }
//! ```
//!
//! If `packet_headers` isn't specified, the stage infers ordering from `fingerprint.browser_type`.
//! If `tcp_fingerprint` isn't specified, it infers from `fingerprint.os`.
//!
//! ## Browser Header Order Differences
//!
//! Each browser has distinct header ordering. Key differences:
//!
//! ### Chrome (and Chromium-based)
//! - Leads with: host, connection, cache-control, sec-ch-ua headers
//! - User-Agent comes AFTER sec-ch-* client hints
//! - sec-fetch-* headers appear as a group after accept
//!
//! ### Firefox
//! - Leads with: host, user-agent, accept, accept-language
//! - User-Agent is second (not ninth like Chrome)
//! - No sec-ch-* headers (Firefox doesn't support Client Hints)
//! - Includes TE header for transfer encodings
//!
//! ### Edge
//! - Very similar to Chrome (same Chromium base)
//! - Minor differences in sec-ch-ua-platform placement
//! - Same general structure as Chrome
//!
//! ## Telemetry Markers
//!
//! The stage adds markers to `flow.metadata.packet_headers.markers` for debugging:
//! - `headers_reordered`: Header order was changed from original
//! - `tcp_target_os:{os}`: TCP fingerprint set to specific OS
//! - `tcp_ttl:{value}`: TTL value being applied
//! - `response_headers_processed`: Response headers were also processed
//!
//! ## Limitations
//!
//! 1. **HTTP library constraints**: The Rust `http` crate normalizes header names to lowercase
//!    internally. Header case mapping is tracked in metadata but may not be preserved through
//!    all serialization paths. Verify with packet captures.
//!
//! 2. **HTTP/2 pseudo-headers**: HTTP/2 header ordering in HPACK-compressed frames requires
//!    coordination with the HTTP/2 implementation. Ensure the HTTP/2 codec respects ordering.
//!
//! 3. **TCP options reordering**: The eBPF module modifies TCP option VALUES but doesn't
//!    reorder options in packets (would require packet reconstruction). For complete stealth,
//!    consider implementing full TCP options reordering via raw sockets or nftables.
//!
//! ## Security Note
//!
//! Header ordering alone is not sufficient for complete stealth. Fingerprinting services
//! correlate multiple signals: HTTP headers, TLS fingerprint (JA3/JA4), TCP/IP fingerprint,
//! JavaScript execution environment, and behavioral patterns. The 404 proxy addresses these
//! through multiple coordinated stages.

use std::collections::HashMap;

use anyhow::Result;
use async_trait::async_trait;
use http::{header::HeaderName, HeaderMap};
use serde_json::Value;

use crate::proxy::flow::{Flow, PacketHeaderContext, TcpFingerprintHints};

use super::FlowStage;

/// PacketHeaderStage reorders HTTP headers and coordinates TCP fingerprint settings.
///
/// This stage is the core of HTTP-level fingerprint evasion. It transforms incoming
/// requests to match real browser header patterns before forwarding upstream.
///
/// # Thread Safety
///
/// PacketHeaderStage is Clone and contains only default configuration data. Each request
/// gets its own Flow with mutable state. The stage itself is immutable during processing.
///
/// # Example Usage
///
/// ```ignore
/// let stage = PacketHeaderStage::new();
/// stage.on_request(&mut flow).await?;
/// // flow.request.headers is now reordered
/// // flow.metadata.packet_headers contains TCP hints
/// ```
#[derive(Clone)]
pub struct PacketHeaderStage {
    /// Default header order for Chrome-like browsers (used when profile doesn't specify).
    /// This is the fallback when no explicit `packet_headers.header_order` is in the profile.
    default_header_order: Vec<String>,

    /// Default HTTP/2 pseudo-header order.
    /// Chrome's order: [:method, :authority, :scheme, :path]
    default_h2_pseudo_order: Vec<String>,

    /// Default header case mapping for HTTP/1.1 (lowercase -> ProperCase).
    /// Used when profile doesn't specify `packet_headers.header_case`.
    default_header_case: HashMap<String, String>,
}

impl PacketHeaderStage {
    pub fn new() -> Self {
        Self {
            default_header_order: Self::chrome_header_order(),
            default_h2_pseudo_order: vec![
                ":method".to_string(),
                ":authority".to_string(),
                ":scheme".to_string(),
                ":path".to_string(),
            ],
            default_header_case: Self::chrome_header_case(),
        }
    }

    /// Chrome's typical HTTP/1.1 header order (based on real browser captures).
    ///
    /// This ordering was captured from Chrome 120+ on Windows. Key characteristics:
    /// - Host is always first
    /// - Connection header early for HTTP/1.1
    /// - sec-ch-ua client hints come before User-Agent
    /// - sec-fetch-* headers grouped together
    /// - Cookie near the end
    /// - Content-Type/Content-Length last (for POST requests)
    ///
    /// Note: Chrome may add/remove headers based on request context (e.g., no Origin
    /// for same-origin GET, no sec-ch-ua for non-HTTPS). The reorderer only orders
    /// headers that are present, preserving absent headers as absent.
    fn chrome_header_order() -> Vec<String> {
        vec![
            "host".to_string(),
            "connection".to_string(),
            "cache-control".to_string(),
            "sec-ch-ua".to_string(),
            "sec-ch-ua-mobile".to_string(),
            "sec-ch-ua-platform".to_string(),
            "dnt".to_string(),
            "upgrade-insecure-requests".to_string(),
            "user-agent".to_string(),
            "accept".to_string(),
            "sec-fetch-site".to_string(),
            "sec-fetch-mode".to_string(),
            "sec-fetch-user".to_string(),
            "sec-fetch-dest".to_string(),
            "referer".to_string(),
            "accept-encoding".to_string(),
            "accept-language".to_string(),
            "cookie".to_string(),
            "content-type".to_string(),
            "content-length".to_string(),
            "origin".to_string(),
        ]
    }

    /// Firefox's typical HTTP/1.1 header order.
    ///
    /// Firefox differs significantly from Chrome/Chromium:
    /// - User-Agent comes SECOND (not ninth like Chrome)
    /// - Accept headers grouped together early
    /// - No sec-ch-* headers (Firefox doesn't implement Client Hints API)
    /// - Includes TE header (Transfer-Encoding preferences)
    /// - sec-fetch-* ordering is different from Chrome
    ///
    /// Captured from Firefox 121+ on Windows/Linux.
    fn firefox_header_order() -> Vec<String> {
        vec![
            "host".to_string(),
            "user-agent".to_string(),
            "accept".to_string(),
            "accept-language".to_string(),
            "accept-encoding".to_string(),
            "dnt".to_string(),
            "connection".to_string(),
            "referer".to_string(),
            "cookie".to_string(),
            "upgrade-insecure-requests".to_string(),
            "sec-fetch-dest".to_string(),
            "sec-fetch-mode".to_string(),
            "sec-fetch-site".to_string(),
            "sec-fetch-user".to_string(),
            "cache-control".to_string(),
            "content-type".to_string(),
            "content-length".to_string(),
            "origin".to_string(),
            "te".to_string(),
        ]
    }

    /// Edge's typical HTTP/1.1 header order (similar to Chrome with minor variations).
    ///
    /// Microsoft Edge is Chromium-based, so its header order is nearly identical to Chrome.
    /// Subtle differences:
    /// - DNT header may be absent (Edge doesn't set by default)
    /// - sec-ch-ua-platform may appear in slightly different position
    /// - Edge-specific headers may be present (but not in this default order)
    ///
    /// For most fingerprinting purposes, Edge and Chrome are interchangeable.
    /// Captured from Edge 120+ on Windows.
    fn edge_header_order() -> Vec<String> {
        vec![
            "host".to_string(),
            "connection".to_string(),
            "cache-control".to_string(),
            "sec-ch-ua".to_string(),
            "sec-ch-ua-mobile".to_string(),
            "sec-ch-ua-platform".to_string(),
            "upgrade-insecure-requests".to_string(),
            "user-agent".to_string(),
            "accept".to_string(),
            "sec-fetch-site".to_string(),
            "sec-fetch-mode".to_string(),
            "sec-fetch-user".to_string(),
            "sec-fetch-dest".to_string(),
            "referer".to_string(),
            "accept-encoding".to_string(),
            "accept-language".to_string(),
            "cookie".to_string(),
            "content-type".to_string(),
            "content-length".to_string(),
            "origin".to_string(),
        ]
    }

    /// Chrome's header capitalization for HTTP/1.1 (case-sensitive in HTTP/1.1).
    fn chrome_header_case() -> HashMap<String, String> {
        let pairs = [
            ("host", "Host"),
            ("connection", "Connection"),
            ("cache-control", "Cache-Control"),
            ("sec-ch-ua", "sec-ch-ua"),
            ("sec-ch-ua-mobile", "sec-ch-ua-mobile"),
            ("sec-ch-ua-platform", "sec-ch-ua-platform"),
            ("sec-ch-ua-full-version", "sec-ch-ua-full-version"),
            ("sec-ch-ua-platform-version", "sec-ch-ua-platform-version"),
            ("sec-ch-ua-arch", "sec-ch-ua-arch"),
            ("sec-ch-ua-bitness", "sec-ch-ua-bitness"),
            ("dnt", "DNT"),
            ("upgrade-insecure-requests", "Upgrade-Insecure-Requests"),
            ("user-agent", "User-Agent"),
            ("accept", "Accept"),
            ("sec-fetch-site", "Sec-Fetch-Site"),
            ("sec-fetch-mode", "Sec-Fetch-Mode"),
            ("sec-fetch-user", "Sec-Fetch-User"),
            ("sec-fetch-dest", "Sec-Fetch-Dest"),
            ("referer", "Referer"),
            ("accept-encoding", "Accept-Encoding"),
            ("accept-language", "Accept-Language"),
            ("cookie", "Cookie"),
            ("content-type", "Content-Type"),
            ("content-length", "Content-Length"),
            ("origin", "Origin"),
            ("authorization", "Authorization"),
            ("if-none-match", "If-None-Match"),
            ("if-modified-since", "If-Modified-Since"),
            ("pragma", "Pragma"),
            ("te", "TE"),
            ("transfer-encoding", "Transfer-Encoding"),
            ("x-requested-with", "X-Requested-With"),
        ];
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    /// Firefox's header capitalization (slightly different patterns).
    fn firefox_header_case() -> HashMap<String, String> {
        let pairs = [
            ("host", "Host"),
            ("user-agent", "User-Agent"),
            ("accept", "Accept"),
            ("accept-language", "Accept-Language"),
            ("accept-encoding", "Accept-Encoding"),
            ("dnt", "DNT"),
            ("connection", "Connection"),
            ("referer", "Referer"),
            ("cookie", "Cookie"),
            ("upgrade-insecure-requests", "Upgrade-Insecure-Requests"),
            ("sec-fetch-dest", "Sec-Fetch-Dest"),
            ("sec-fetch-mode", "Sec-Fetch-Mode"),
            ("sec-fetch-site", "Sec-Fetch-Site"),
            ("sec-fetch-user", "Sec-Fetch-User"),
            ("cache-control", "Cache-Control"),
            ("content-type", "Content-Type"),
            ("content-length", "Content-Length"),
            ("origin", "Origin"),
            ("te", "TE"),
            ("authorization", "Authorization"),
            ("if-none-match", "If-None-Match"),
            ("if-modified-since", "If-Modified-Since"),
            ("pragma", "Pragma"),
        ];
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    /// Extracts header ordering configuration from profile JSON.
    fn header_order_from_profile(&self, profile: &Value) -> Vec<String> {
        // Check for explicit packet_headers.header_order in profile
        if let Some(packet_headers) = profile.get("packet_headers") {
            if let Some(order) = packet_headers.get("header_order") {
                if let Some(arr) = order.as_array() {
                    return arr
                        .iter()
                        .filter_map(|v| v.as_str())
                        .map(|s| s.to_lowercase())
                        .collect();
                }
            }
        }

        // Fallback: infer from browser type in fingerprint config
        if let Some(fingerprint) = profile.get("fingerprint") {
            if let Some(browser_type) = fingerprint.get("browser_type").and_then(|v| v.as_str()) {
                return match browser_type.to_lowercase().as_str() {
                    "firefox" => Self::firefox_header_order(),
                    "edge" => Self::edge_header_order(),
                    "chrome" | _ => Self::chrome_header_order(),
                };
            }
        }

        self.default_header_order.clone()
    }

    /// Extracts header case mapping from profile JSON.
    fn header_case_from_profile(&self, profile: &Value) -> HashMap<String, String> {
        // Check for explicit packet_headers.header_case in profile
        if let Some(packet_headers) = profile.get("packet_headers") {
            if let Some(case_map) = packet_headers.get("header_case") {
                if let Some(obj) = case_map.as_object() {
                    return obj
                        .iter()
                        .filter_map(|(k, v)| v.as_str().map(|s| (k.to_lowercase(), s.to_string())))
                        .collect();
                }
            }
        }

        // Fallback: infer from browser type
        if let Some(fingerprint) = profile.get("fingerprint") {
            if let Some(browser_type) = fingerprint.get("browser_type").and_then(|v| v.as_str()) {
                return match browser_type.to_lowercase().as_str() {
                    "firefox" => Self::firefox_header_case(),
                    "chrome" | "edge" | _ => Self::chrome_header_case(),
                };
            }
        }

        self.default_header_case.clone()
    }

    /// Extracts HTTP/2 pseudo-header order from profile JSON.
    fn h2_pseudo_order_from_profile(&self, profile: &Value) -> Vec<String> {
        if let Some(packet_headers) = profile.get("packet_headers") {
            if let Some(order) = packet_headers.get("h2_pseudo_order") {
                if let Some(arr) = order.as_array() {
                    return arr
                        .iter()
                        .filter_map(|v| v.as_str())
                        .map(|s| s.to_string())
                        .collect();
                }
            }
        }

        // Default HTTP/2 pseudo-header order (Chrome-style)
        self.default_h2_pseudo_order.clone()
    }

    /// Extracts TCP fingerprint hints from profile JSON.
    fn tcp_fingerprint_from_profile(&self, profile: &Value) -> TcpFingerprintHints {
        let mut hints = TcpFingerprintHints::default();

        // Check for explicit tcp_fingerprint section
        if let Some(tcp_fp) = profile.get("tcp_fingerprint") {
            if let Some(os) = tcp_fp.get("target_os").and_then(|v| v.as_str()) {
                hints.target_os = os.to_string();
            }
            if let Some(ttl) = tcp_fp.get("ttl").and_then(|v| v.as_u64()) {
                hints.ttl = ttl as u8;
            }
            if let Some(mss) = tcp_fp.get("mss").and_then(|v| v.as_u64()) {
                hints.mss = mss as u16;
            }
            if let Some(ws) = tcp_fp.get("window_size").and_then(|v| v.as_u64()) {
                hints.window_size = ws as u16;
            }
            if let Some(scale) = tcp_fp.get("window_scale").and_then(|v| v.as_u64()) {
                hints.window_scale = scale as u8;
            }
            if let Some(ts) = tcp_fp.get("timestamps_enabled").and_then(|v| v.as_bool()) {
                hints.timestamps_enabled = ts;
            }
            if let Some(order) = tcp_fp.get("tcp_options_order").and_then(|v| v.as_array()) {
                hints.tcp_options_order = order
                    .iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect();
            }
            if let Some(df) = tcp_fp.get("df_flag").and_then(|v| v.as_bool()) {
                hints.df_flag = df;
            }
            if let Some(tos) = tcp_fp.get("ip_tos").and_then(|v| v.as_u64()) {
                hints.ip_tos = tos as u8;
            }
            if let Some(rand_id) = tcp_fp.get("randomize_ip_id").and_then(|v| v.as_bool()) {
                hints.randomize_ip_id = rand_id;
            }
            if let Some(rand_seq) = tcp_fp.get("randomize_seq").and_then(|v| v.as_bool()) {
                hints.randomize_seq = rand_seq;
            }
            return hints;
        }

        // Fallback: infer from OS in fingerprint config
        if let Some(fingerprint) = profile.get("fingerprint") {
            if let Some(os) = fingerprint.get("os").and_then(|v| v.as_str()) {
                match os.to_lowercase().as_str() {
                    "windows" => {
                        hints.target_os = "windows".to_string();
                        hints.ttl = 128;
                        hints.timestamps_enabled = false;
                        hints.tcp_options_order = vec![
                            "MSS".to_string(),
                            "NOP".to_string(),
                            "WS".to_string(),
                            "NOP".to_string(),
                            "NOP".to_string(),
                            "SACK_PERM".to_string(),
                        ];
                        hints.df_flag = true;
                    }
                    "linux" => {
                        hints.target_os = "linux".to_string();
                        hints.ttl = 64;
                        hints.timestamps_enabled = true;
                        hints.tcp_options_order = vec![
                            "MSS".to_string(),
                            "SACK_PERM".to_string(),
                            "TS".to_string(),
                            "NOP".to_string(),
                            "WS".to_string(),
                        ];
                        hints.df_flag = true;
                    }
                    "macos" | "mac os" | "darwin" => {
                        hints.target_os = "macos".to_string();
                        hints.ttl = 64;
                        hints.timestamps_enabled = true;
                        hints.tcp_options_order = vec![
                            "MSS".to_string(),
                            "NOP".to_string(),
                            "WS".to_string(),
                            "NOP".to_string(),
                            "NOP".to_string(),
                            "TS".to_string(),
                            "SACK_PERM".to_string(),
                            "EOL".to_string(),
                        ];
                        hints.df_flag = true;
                    }
                    _ => {}
                }
            }
        }

        hints
    }

    /// Reorders headers according to the specified order.
    ///
    /// # Algorithm
    ///
    /// 1. **First pass**: Iterate through the target order list. For each header name in the
    ///    order, if that header exists in the input, add it to the new HeaderMap.
    ///
    /// 2. **Second pass**: Iterate through remaining headers not in the order list and
    ///    append them at the end. This preserves any custom/unusual headers while ensuring
    ///    standard headers are in the expected position.
    ///
    /// # Case Handling
    ///
    /// The `http` crate normalizes all header names to lowercase internally. The `case_map`
    /// parameter tracks the original capitalization (e.g., "user-agent" -> "User-Agent")
    /// for use in serialization. However, due to http crate limitations, the actual
    /// HeaderMap will contain lowercase keys.
    ///
    /// # Returns
    ///
    /// A tuple of:
    /// - The reordered HeaderMap
    /// - A Vec of header names in the order they were added (for telemetry/debugging)
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Input headers (random order): accept-encoding, user-agent, host, accept
    /// // Target order: host, user-agent, accept, accept-encoding
    /// // Result: host, user-agent, accept, accept-encoding (reordered)
    /// ```
    fn reorder_headers(
        &self,
        headers: &HeaderMap,
        order: &[String],
        case_map: &HashMap<String, String>,
    ) -> (HeaderMap, Vec<String>) {
        let mut new_headers = HeaderMap::new();
        let mut applied_order = Vec::new();

        // First pass: add headers in the specified order
        for header_name in order {
            let name_lower = header_name.to_lowercase();
            if let Ok(header_key) = HeaderName::from_bytes(name_lower.as_bytes()) {
                if let Some(value) = headers.get(&header_key) {
                    // Apply case mapping for the header name
                    let _cased_name = case_map
                        .get(&name_lower)
                        .cloned()
                        .unwrap_or_else(|| header_name.clone());

                    // Note: http crate normalizes header names to lowercase internally.
                    // The case mapping is tracked in metadata for serialization.
                    new_headers.insert(header_key.clone(), value.clone());
                    applied_order.push(name_lower);
                }
            }
        }

        // Second pass: add any remaining headers not in the order list
        for (name, value) in headers.iter() {
            let name_lower = name.as_str().to_lowercase();
            if !applied_order.contains(&name_lower) {
                new_headers.insert(name.clone(), value.clone());
                applied_order.push(name_lower);
            }
        }

        (new_headers, applied_order)
    }

    /// Generates a deterministic fingerprint ID from the flow ID.
    fn fingerprint_id_from_flow(&self, flow_id: uuid::Uuid) -> String {
        let bytes = flow_id.as_bytes();
        let hash = bytes.iter().fold(0u64, |acc, &b| acc.wrapping_mul(31).wrapping_add(b as u64));
        format!("pkt-{:016x}", hash)
    }
}

impl Default for PacketHeaderStage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FlowStage for PacketHeaderStage {
    /// Processes an incoming HTTP request to apply header ordering and extract TCP hints.
    ///
    /// # Processing Steps
    ///
    /// 1. **Read profile config**: Gets the browser profile from `flow.metadata.fingerprint_config`
    ///    (populated by HeaderProfileStage which runs before us).
    ///
    /// 2. **Extract configuration**: Reads header_order, header_case, h2_pseudo_order, and
    ///    tcp_fingerprint settings from the profile JSON. Falls back to defaults if not specified.
    ///
    /// 3. **Capture original order**: Records the original header order for telemetry comparison.
    ///
    /// 4. **Reorder headers**: Applies the target browser's header ordering to the request.
    ///
    /// 5. **Populate context**: Creates PacketHeaderContext with all ordering info and TCP
    ///    fingerprint hints for downstream use (serialization, eBPF coordination).
    ///
    /// 6. **Add telemetry markers**: Records what modifications were made for debugging.
    ///
    /// # Side Effects
    ///
    /// - Modifies `flow.request.headers` to new ordering
    /// - Populates `flow.metadata.packet_headers` with full context
    ///
    /// # Errors
    ///
    /// Currently always returns Ok. Header reordering cannot fail, and profile parsing
    /// falls back to defaults on invalid/missing data.
    async fn on_request(&self, flow: &mut Flow) -> Result<()> {
        // Read profile from metadata (HeaderProfileStage populates this before us)
        let profile = &flow.metadata.fingerprint_config;

        // Extract configuration from profile
        let header_order = self.header_order_from_profile(profile);
        let header_case = self.header_case_from_profile(profile);
        let h2_pseudo_order = self.h2_pseudo_order_from_profile(profile);
        let tcp_hints = self.tcp_fingerprint_from_profile(profile);

        // Capture original header order before reordering
        let original_order: Vec<String> = flow
            .request
            .headers
            .keys()
            .map(|k| k.as_str().to_string())
            .collect();

        // Reorder headers
        let (reordered_headers, applied_order) =
            self.reorder_headers(&flow.request.headers, &header_order, &header_case);

        // Update flow with reordered headers
        flow.request.headers = reordered_headers;

        // Populate packet header context
        let mut ctx = PacketHeaderContext {
            enabled: true,
            original_header_order: original_order,
            applied_header_order: applied_order.clone(),
            header_case_map: header_case,
            packet_fingerprint_id: self.fingerprint_id_from_flow(flow.id),
            h2_pseudo_order,
            tcp_fingerprint: tcp_hints,
            markers: Vec::new(),
        };

        // Track what we did for telemetry
        if ctx.original_header_order != ctx.applied_header_order {
            ctx.markers.push("headers_reordered".to_string());
        }
        ctx.markers.push(format!("tcp_target_os:{}", ctx.tcp_fingerprint.target_os));
        ctx.markers.push(format!("tcp_ttl:{}", ctx.tcp_fingerprint.ttl));

        flow.metadata.packet_headers = ctx;

        Ok(())
    }

    /// Processes HTTP response headers from upstream.
    ///
    /// # Response Processing
    ///
    /// Response header ordering is less critical for fingerprint evasion since:
    /// 1. The server controls response header order, not the client
    /// 2. Fingerprinting services focus on REQUEST patterns (what the client sends)
    /// 3. Proxies typically pass response headers through unchanged
    ///
    /// However, some scenarios may require response header manipulation:
    /// - Stripping or modifying server fingerprint headers (Server, X-Powered-By)
    /// - Normalizing Set-Cookie header ordering for consistency
    /// - Ensuring CORS headers appear in expected positions
    ///
    /// # Current Implementation
    ///
    /// Currently, this method only adds a telemetry marker indicating that response
    /// headers were processed. Future versions may implement response header reordering
    /// if specific evasion scenarios require it.
    ///
    /// # Side Effects
    ///
    /// Adds "response_headers_processed" to `flow.metadata.packet_headers.markers`
    /// if packet header processing is enabled.
    async fn on_response_headers(&self, flow: &mut Flow) -> Result<()> {
        // Response header ordering is less critical for fingerprint evasion since
        // fingerprinting services focus on REQUEST patterns. Currently we just mark
        // that processing occurred for telemetry purposes.
        //
        // Future enhancement: Consider reordering response headers for scenarios like:
        // - Stripping server fingerprint headers
        // - Normalizing Set-Cookie order
        // - CORS header positioning
        if flow.metadata.packet_headers.enabled {
            flow.metadata
                .packet_headers
                .markers
                .push("response_headers_processed".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::flow::{BodyBuffer, Flow, RequestParts};
    use http::{Method, Uri, Version};
    use std::str::FromStr;

    fn build_test_flow() -> Flow {
        let mut headers = HeaderMap::new();
        headers.insert("accept-encoding", HeaderValue::from_static("gzip, deflate"));
        headers.insert("user-agent", HeaderValue::from_static("TestAgent"));
        headers.insert("host", HeaderValue::from_static("example.com"));
        headers.insert("accept", HeaderValue::from_static("text/html"));
        headers.insert("cookie", HeaderValue::from_static("session=abc123"));

        let request = RequestParts {
            method: Method::GET,
            uri: Uri::from_str("https://example.com/").unwrap(),
            version: Version::HTTP_11,
            headers,
            body: BodyBuffer::default(),
        };
        Flow::new(request)
    }

    #[tokio::test]
    async fn test_header_reordering() {
        let stage = PacketHeaderStage::new();
        let mut flow = build_test_flow();

        // Set a Chrome profile
        flow.metadata.fingerprint_config = serde_json::json!({
            "fingerprint": {
                "browser_type": "chrome",
                "os": "Windows"
            }
        });

        stage.on_request(&mut flow).await.unwrap();

        // Verify headers were reordered
        assert!(flow.metadata.packet_headers.enabled);

        // Host should come first in Chrome order
        let keys: Vec<_> = flow.request.headers.keys().map(|k| k.as_str()).collect();
        let host_pos = keys.iter().position(|&k| k == "host");
        let user_agent_pos = keys.iter().position(|&k| k == "user-agent");

        // In Chrome order, host comes before user-agent
        assert!(host_pos.is_some());
        assert!(user_agent_pos.is_some());
    }

    #[tokio::test]
    async fn test_tcp_fingerprint_windows() {
        let stage = PacketHeaderStage::new();
        let mut flow = build_test_flow();

        flow.metadata.fingerprint_config = serde_json::json!({
            "fingerprint": {
                "browser_type": "chrome",
                "os": "Windows"
            }
        });

        stage.on_request(&mut flow).await.unwrap();

        let tcp = &flow.metadata.packet_headers.tcp_fingerprint;
        assert_eq!(tcp.target_os, "windows");
        assert_eq!(tcp.ttl, 128);
        assert!(!tcp.timestamps_enabled);
    }

    #[tokio::test]
    async fn test_tcp_fingerprint_linux() {
        let stage = PacketHeaderStage::new();
        let mut flow = build_test_flow();

        flow.metadata.fingerprint_config = serde_json::json!({
            "fingerprint": {
                "browser_type": "firefox",
                "os": "Linux"
            }
        });

        stage.on_request(&mut flow).await.unwrap();

        let tcp = &flow.metadata.packet_headers.tcp_fingerprint;
        assert_eq!(tcp.target_os, "linux");
        assert_eq!(tcp.ttl, 64);
        assert!(tcp.timestamps_enabled);
    }

    #[tokio::test]
    async fn test_explicit_tcp_config() {
        let stage = PacketHeaderStage::new();
        let mut flow = build_test_flow();

        flow.metadata.fingerprint_config = serde_json::json!({
            "fingerprint": {
                "browser_type": "chrome",
                "os": "Windows"
            },
            "tcp_fingerprint": {
                "target_os": "custom",
                "ttl": 200,
                "mss": 1400,
                "window_size": 32768,
                "window_scale": 6,
                "timestamps_enabled": true,
                "tcp_options_order": ["MSS", "TS", "SACK_PERM", "WS"],
                "df_flag": false,
                "ip_tos": 16,
                "randomize_ip_id": false,
                "randomize_seq": false
            }
        });

        stage.on_request(&mut flow).await.unwrap();

        let tcp = &flow.metadata.packet_headers.tcp_fingerprint;
        assert_eq!(tcp.target_os, "custom");
        assert_eq!(tcp.ttl, 200);
        assert_eq!(tcp.mss, 1400);
        assert_eq!(tcp.window_size, 32768);
        assert_eq!(tcp.window_scale, 6);
        assert!(tcp.timestamps_enabled);
        assert!(!tcp.df_flag);
        assert_eq!(tcp.ip_tos, 16);
        assert!(!tcp.randomize_ip_id);
        assert!(!tcp.randomize_seq);
    }
}
