//! Memory & RAG inventory + poisoning surface (INC-8, Stage B explainability).
//!
//! Projects the discovered MCP endpoints into an inventory of the agent's
//! **memory / retrieval backends** -- vector databases (Pinecone, Qdrant,
//! Weaviate, Chroma, Milvus, pgvector, LanceDB, FAISS), key-value / memory
//! services (Mem0, Redis, Letta/MemGPT), and search backends (Elasticsearch,
//! OpenSearch) -- classified by kind, exposure, and auth, with a deterministic
//! *poisoning / exfiltration surface* severity per store.
//!
//! This is a config-derived inventory (the analogue of the MCP inventory): it
//! does NOT connect to the store or read chunks (I5). Live chunk-risk scoring
//! and provenance DAGs are a later, connector-backed increment; the shape here
//! is the deterministic surface map.
//!
//! Invariants:
//! - **I3 Deterministic-first**: classification + severity from the rules below.
//! - **I5 Privacy tiers**: only metadata (store kind, server name, exposure,
//!   auth) is carried -- never chunk/embedding bodies.
//! - Findings reuse `VisibilityFinding` so the dismissal model (I4) applies.

use crate::agent_visibility::{short_hash, VisibilityFinding, VisibilitySeverity};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Raw input (foundation-local; core maps MCP endpoints in)
// ---------------------------------------------------------------------------

/// A flattened MCP endpoint for the memory/RAG classifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawMemoryEndpoint {
    pub agent_type: String,
    pub id: String,
    pub server_name: String,
    pub command: Option<String>,
    pub url: Option<String>,
    /// `ExposureScope` snake string.
    pub exposure: String,
    /// `AuthStrength` snake string.
    pub auth: String,
    pub is_edamame: bool,
}

// ---------------------------------------------------------------------------
// Output projection
// ---------------------------------------------------------------------------

/// Kind of memory / retrieval backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryStoreKind {
    /// Dedicated vector database (Pinecone, Qdrant, Weaviate, Chroma, ...).
    VectorDb,
    /// Long-term agent memory service (Mem0, Letta/MemGPT).
    MemoryService,
    /// Key-value store used as memory (Redis, ...).
    KeyValue,
    /// Full-text search backend (Elasticsearch, OpenSearch).
    SearchEngine,
}

impl MemoryStoreKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            MemoryStoreKind::VectorDb => "vector_db",
            MemoryStoreKind::MemoryService => "memory_service",
            MemoryStoreKind::KeyValue => "key_value",
            MemoryStoreKind::SearchEngine => "search_engine",
        }
    }
    pub fn label(&self) -> &'static str {
        match self {
            MemoryStoreKind::VectorDb => "Vector DB",
            MemoryStoreKind::MemoryService => "Memory Service",
            MemoryStoreKind::KeyValue => "Key-Value Store",
            MemoryStoreKind::SearchEngine => "Search Engine",
        }
    }
}

/// One discovered memory / RAG store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryStore {
    /// Stable id over (agent, server, kind).
    pub store_id: String,
    pub agent_type: String,
    pub server_name: String,
    pub kind: MemoryStoreKind,
    /// The vendor/product keyword that matched (e.g. `qdrant`).
    pub product: String,
    pub exposure: String,
    pub auth: String,
    /// Poisoning / exfiltration surface severity.
    pub severity: VisibilitySeverity,
    pub summary: String,
}

/// Inventory of all memory / RAG stores across discovered agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryInventory {
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub stores: Vec<MemoryStore>,
    /// HIGH/CRITICAL store count (alertable gate).
    pub alertable_store_count: u32,
    pub findings: Vec<VisibilityFinding>,
}

// ---------------------------------------------------------------------------
// Classification tables (deterministic; refinable by CloudModel later)
// ---------------------------------------------------------------------------

/// (keyword, product, kind). First match wins; longer/more-specific keywords
/// listed first so e.g. `pgvector` matches before a bare `postgres`.
const MEMORY_KEYWORDS: &[(&str, &str, MemoryStoreKind)] = &[
    ("pinecone", "pinecone", MemoryStoreKind::VectorDb),
    ("qdrant", "qdrant", MemoryStoreKind::VectorDb),
    ("weaviate", "weaviate", MemoryStoreKind::VectorDb),
    ("chroma", "chroma", MemoryStoreKind::VectorDb),
    ("milvus", "milvus", MemoryStoreKind::VectorDb),
    ("pgvector", "pgvector", MemoryStoreKind::VectorDb),
    ("lancedb", "lancedb", MemoryStoreKind::VectorDb),
    ("faiss", "faiss", MemoryStoreKind::VectorDb),
    ("marqo", "marqo", MemoryStoreKind::VectorDb),
    ("vectorize", "vectorize", MemoryStoreKind::VectorDb),
    ("mem0", "mem0", MemoryStoreKind::MemoryService),
    ("memgpt", "memgpt", MemoryStoreKind::MemoryService),
    ("letta", "letta", MemoryStoreKind::MemoryService),
    ("zep", "zep", MemoryStoreKind::MemoryService),
    ("opensearch", "opensearch", MemoryStoreKind::SearchEngine),
    (
        "elasticsearch",
        "elasticsearch",
        MemoryStoreKind::SearchEngine,
    ),
    ("elastic", "elastic", MemoryStoreKind::SearchEngine),
    ("redis", "redis", MemoryStoreKind::KeyValue),
    // Generic catch-alls last.
    ("vector", "vector-db", MemoryStoreKind::VectorDb),
    ("embedding", "embedding-store", MemoryStoreKind::VectorDb),
    ("memory", "memory-store", MemoryStoreKind::MemoryService),
    ("rag", "rag-backend", MemoryStoreKind::VectorDb),
];

fn classify(ep: &RawMemoryEndpoint) -> Option<(MemoryStoreKind, String)> {
    let hay = format!(
        "{} {} {}",
        ep.server_name.to_ascii_lowercase(),
        ep.command.as_deref().unwrap_or("").to_ascii_lowercase(),
        ep.url.as_deref().unwrap_or("").to_ascii_lowercase(),
    );
    for (kw, product, kind) in MEMORY_KEYWORDS {
        if hay.contains(kw) {
            return Some((*kind, product.to_string()));
        }
    }
    None
}

fn cross_boundary(exposure: &str) -> bool {
    matches!(
        exposure.trim().to_ascii_lowercase().as_str(),
        "lan" | "remote" | "public"
    )
}

fn weak_auth(auth: &str) -> bool {
    matches!(
        auth.trim().to_ascii_lowercase().as_str(),
        "none" | "unknown"
    )
}

/// Poisoning / exfiltration surface severity for a memory store. A store the
/// agent reads context from is a poisoning vector (untrusted content -> model
/// context); a writable/remote store with weak auth is also an exfil vector.
fn store_severity(exposure: &str, auth: &str) -> VisibilitySeverity {
    let cross = cross_boundary(exposure);
    let weak = weak_auth(auth);
    if cross && weak {
        // Reachable across a trust boundary with no/unknown auth: anyone on
        // that surface can poison the corpus or read it back.
        VisibilitySeverity::High
    } else if cross {
        VisibilitySeverity::Medium
    } else if weak {
        // Local but unauthenticated: a co-resident process can tamper.
        VisibilitySeverity::Low
    } else {
        VisibilitySeverity::Info
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Build the memory / RAG inventory from all discovered MCP endpoints. Pure.
pub fn build_memory_inventory(endpoints: &[RawMemoryEndpoint]) -> MemoryInventory {
    let mut stores: Vec<MemoryStore> = Vec::new();
    for ep in endpoints.iter().filter(|e| !e.is_edamame) {
        let Some((kind, product)) = classify(ep) else {
            continue;
        };
        let severity = store_severity(&ep.exposure, &ep.auth);
        let store_id = format!(
            "mem-{}",
            short_hash(&format!(
                "{}:{}:{}",
                ep.agent_type,
                ep.server_name,
                kind.as_str()
            ))
        );
        let summary = format!(
            "{} ({}) reachable {} with {} auth",
            kind.label(),
            product,
            ep.exposure,
            ep.auth
        );
        stores.push(MemoryStore {
            store_id,
            agent_type: ep.agent_type.clone(),
            server_name: ep.server_name.clone(),
            kind,
            product,
            exposure: ep.exposure.clone(),
            auth: ep.auth.clone(),
            severity,
            summary,
        });
    }

    stores.sort_by(|a, b| {
        severity_rank(b.severity)
            .cmp(&severity_rank(a.severity))
            .then_with(|| a.agent_type.cmp(&b.agent_type))
            .then_with(|| a.server_name.cmp(&b.server_name))
    });

    let alertable_store_count = stores.iter().filter(|s| s.severity.is_alertable()).count() as u32;
    let findings = derive_findings(&stores);

    MemoryInventory {
        generated_at: chrono::Utc::now(),
        stores,
        alertable_store_count,
        findings,
    }
}

fn severity_rank(s: VisibilitySeverity) -> u8 {
    match s {
        VisibilitySeverity::Critical => 5,
        VisibilitySeverity::High => 4,
        VisibilitySeverity::Medium => 3,
        VisibilitySeverity::Low => 2,
        VisibilitySeverity::Info => 1,
    }
}

fn derive_findings(stores: &[MemoryStore]) -> Vec<VisibilityFinding> {
    let mut findings = Vec::new();
    for s in stores.iter().filter(|s| s.severity.is_alertable()) {
        findings.push(
            VisibilityFinding::new(
                "memory",
                "memory_poisoning_surface",
                s.severity,
                &s.store_id,
                format!("exposed {} on {}", s.kind.label(), s.agent_type),
                format!(
                    "{} -- a cross-boundary, weakly-authenticated retrieval store is a corpus-poisoning and data-exfiltration surface.",
                    s.summary
                ),
            )
            .with_evidence("agent_type", s.agent_type.clone())
            .with_evidence("store_kind", s.kind.as_str())
            .with_evidence("product", s.product.clone())
            .with_evidence("exposure", s.exposure.clone())
            .with_evidence("auth", s.auth.clone())
            .with_owasp(),
        );
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(name: &str, url: Option<&str>, exposure: &str, auth: &str) -> RawMemoryEndpoint {
        RawMemoryEndpoint {
            agent_type: "claude_code".to_string(),
            id: format!("id-{}", name),
            server_name: name.to_string(),
            command: None,
            url: url.map(|s| s.to_string()),
            exposure: exposure.to_string(),
            auth: auth.to_string(),
            is_edamame: false,
        }
    }

    #[test]
    fn detects_remote_vector_db_as_high() {
        let endpoints = vec![ep(
            "qdrant-mcp",
            Some("https://xyz.qdrant.io"),
            "remote",
            "none",
        )];
        let inv = build_memory_inventory(&endpoints);
        assert_eq!(inv.stores.len(), 1);
        assert_eq!(inv.stores[0].kind, MemoryStoreKind::VectorDb);
        assert_eq!(inv.stores[0].severity, VisibilitySeverity::High);
        assert_eq!(inv.alertable_store_count, 1);
        assert!(inv
            .findings
            .iter()
            .any(|f| f.rule_id == "memory_poisoning_surface"));
    }

    #[test]
    fn local_authed_store_is_info() {
        let endpoints = vec![ep("mem0", None, "stdio", "oauth")];
        let inv = build_memory_inventory(&endpoints);
        assert_eq!(inv.stores.len(), 1);
        assert_eq!(inv.stores[0].kind, MemoryStoreKind::MemoryService);
        assert_eq!(inv.stores[0].severity, VisibilitySeverity::Info);
        assert_eq!(inv.alertable_store_count, 0);
    }

    #[test]
    fn non_memory_servers_are_skipped() {
        let endpoints = vec![ep(
            "github",
            Some("https://api.github.com"),
            "remote",
            "oauth",
        )];
        let inv = build_memory_inventory(&endpoints);
        assert!(inv.stores.is_empty());
    }

    #[test]
    fn edamame_server_is_skipped() {
        let mut e = ep("qdrant", Some("https://q.io"), "remote", "none");
        e.is_edamame = true;
        let inv = build_memory_inventory(&[e]);
        assert!(inv.stores.is_empty());
    }
}
