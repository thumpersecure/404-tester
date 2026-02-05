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

/// # Flow Stages - HTTP Request/Response Processing Pipeline
///
/// Flow stages replicate the mitmproxy addon chain that lives under `src/proxy/AOs/` in the
/// legacy tree. Each stage implements [`FlowStage`] and the `StagePipeline` drives them in
/// the same deterministic order so HTTP request/response mutations stay identical between
/// the Python prototype and `static_proxy/src/proxy/stages/`.
///
/// ## Stage Ordering (Critical for Correctness)
///
/// Stages run in a specific order. Each stage may depend on data populated by earlier stages:
///
/// ```text
/// REQUEST FLOW (left to right):
/// ┌──────────────┐   ┌───────────────┐   ┌───────────────┐   ┌─────────────────┐
/// │    Cookie    │ → │ HeaderProfile │ → │ PacketHeaders │ → │ BehavioralNoise │ → ...
/// │  Isolation   │   │   (loads      │   │  (reorders    │   │                 │
/// │              │   │    profile)   │   │   headers)    │   │                 │
/// └──────────────┘   └───────────────┘   └───────────────┘   └─────────────────┘
///        ↓                  ↓                   ↓                    ↓
///    partitions         sets             needs profile        may add headers
///    cookies by      fingerprint_config  config from prev
///    top-site
/// ```
///
/// ## Stage Responsibilities
///
/// 1. **CookieIsolationStage**: Partitions cookies by top-level site (eTLD+1) to prevent
///    cross-site tracking. Uses Public Suffix List for domain classification.
///
/// 2. **HeaderProfileStage**: Loads browser profile JSON, sets User-Agent, populates
///    `flow.metadata.fingerprint_config` for downstream stages.
///
/// 3. **PacketHeaderStage**: Reorders HTTP headers to match browser fingerprints.
///    Extracts TCP fingerprint hints for eBPF coordination. MUST run after HeaderProfileStage.
///
/// 4. **BehavioralNoiseStage**: Adds timing variations and request patterns to mimic
///    human behavior. May inject additional headers or delays.
///
/// 5. **CspStage**: Handles Content-Security-Policy headers, injects nonces for inline
///    scripts, stores original CSP for later restoration.
///
/// 6. **JsInjectionStage**: Injects JavaScript for fingerprint spoofing, canvas noise,
///    WebGL modifications, etc. Uses nonces from CspStage.
///
/// 7. **AltSvcStage**: Manages Alt-Svc headers to control HTTP/2 and HTTP/3 upgrades.
///
/// ## Adding New Stages
///
/// To add a new stage:
/// 1. Create a new module file (e.g., `my_stage.rs`)
/// 2. Implement `FlowStage` trait
/// 3. Add `mod my_stage;` and `pub use my_stage::MyStage;` below
/// 4. Add `stages.push(Arc::new(MyStage::new()));` in `StagePipeline::build()` at correct position
/// 5. Document any stage ordering dependencies

mod alt_svc;
mod behavior;
mod csp;
mod cookie;
mod header_profile;
mod js;
mod packet_headers;

pub use alt_svc::AltSvcStage;
pub use behavior::BehavioralNoiseStage;
pub use csp::CspStage;
pub use cookie::CookieIsolationStage;
pub use header_profile::HeaderProfileStage;
pub use js::JsInjectionStage;
pub use packet_headers::PacketHeaderStage;

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;

use crate::{config::PipelineConfig, proxy::flow::Flow, telemetry::TelemetrySink};

#[derive(Clone)]
/// Represents the ordered pipeline of addon stages run for every flow.
pub struct StagePipeline {
    inner: Arc<PipelineInner>,
}

struct PipelineInner {
    stages: Vec<Arc<dyn FlowStage>>,
}

impl StagePipeline {
    /// Builds the pipeline with deterministic ordering so request mutations always happen before
    /// CSP/JS stages and response sanitizers run after script injection.
    pub fn build(cfg: &PipelineConfig, _telemetry: TelemetrySink) -> Result<Self> {
        let mut stages: Vec<Arc<dyn FlowStage>> = Vec::new();

        let psl = Arc::new(publicsuffix::List::new());
        stages.push(Arc::new(CookieIsolationStage::new(psl)));

        // HeaderProfileStage MUST be early - it loads browser profile JSON into
        // flow.metadata.fingerprint_config which downstream stages depend on.
        stages.push(Arc::new(HeaderProfileStage::new(
            cfg.profiles_path.clone(),
            cfg.default_profile.clone(),
        )?));

        // PacketHeaderStage - CRITICAL FOR STEALTH
        // Must run AFTER HeaderProfileStage to access fingerprint_config.
        // Does:
        //   1. Reorders HTTP headers to match browser-specific patterns (Chrome/Firefox/Edge)
        //   2. Maps header capitalization for HTTP/1.1 (case-sensitive on wire)
        //   3. Sets HTTP/2 pseudo-header ordering (:method, :authority, :scheme, :path)
        //   4. Extracts TCP fingerprint hints (TTL, MSS, window size) for eBPF module
        // The TCP hints in flow.metadata.packet_headers.tcp_fingerprint should be
        // pushed to the eBPF fingerprint_settings map for kernel-level spoofing.
        stages.push(Arc::new(PacketHeaderStage::new()));
        stages.push(Arc::new(BehavioralNoiseStage::new()));
        stages.push(Arc::new(CspStage::default()));
        stages.push(Arc::new(JsInjectionStage::new(cfg.js_debug)));
        stages.push(Arc::new(AltSvcStage::new(cfg.alt_svc_strategy.clone())));

        Ok(Self {
            inner: Arc::new(PipelineInner { stages }),
        })
    }

    pub async fn process_request(&self, flow: &mut Flow) -> Result<()> {
        for stage in &self.inner.stages {
            stage.on_request(flow).await?;
        }
        Ok(())
    }

    pub async fn process_response_headers(&self, flow: &mut Flow) -> Result<()> {
        for stage in &self.inner.stages {
            stage.on_response_headers(flow).await?;
        }
        Ok(())
    }

    pub async fn process_response_body(&self, flow: &mut Flow) -> Result<()> {
        for stage in &self.inner.stages {
            stage.on_response_body(flow).await?;
        }
        Ok(())
    }

    pub async fn finalize_response(&self, flow: &mut Flow) -> Result<()> {
        for stage in &self.inner.stages {
            stage.on_response_finalized(flow).await?;
        }
        Ok(())
    }
}

#[async_trait]

pub trait FlowStage: Send + Sync {
    async fn on_request(&self, _flow: &mut Flow) -> Result<()> {
        
        Ok(())
    }

    async fn on_response_headers(&self, _flow: &mut Flow) -> Result<()> {
        Ok(())
    }

    async fn on_response_body(&self, _flow: &mut Flow) -> Result<()> {
        Ok(())
    }

    async fn on_response_finalized(&self, _flow: &mut Flow) -> Result<()> {
        Ok(())
    }
}
