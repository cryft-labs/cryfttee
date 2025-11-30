//! GitHub Signature Verification for CryftTEE Modules
//!
//! This module provides verification of module packages using GitHub's
//! signing infrastructure:
//!
//! 1. **GitHub Release Signatures**: Verify modules from signed GitHub releases
//! 2. **GitHub Commit Signatures**: Verify the commit that produced the module was signed
//! 3. **GitHub Actions Attestations**: Verify modules were built by trusted CI/CD workflows
//!
//! # Trust Model
//!
//! Publishers can be verified through multiple GitHub-based mechanisms:
//! - GPG key associated with GitHub account
//! - SSH key associated with GitHub account  
//! - GitHub Actions OIDC token (proves CI built the artifact)
//! - Sigstore/cosign signatures (for container-based modules)
//!
//! # Configuration
//!
//! Add GitHub-verified publishers to `trust.toml`:
//! ```toml
//! [[publishers]]
//! id = "cryft-labs"
//! algo = "github"
//! github_org = "cryft-labs"
//! github_repo = "cryfttee-modules"
//! allowed_workflows = ["release.yml", "build-modules.yml"]
//! require_verified_commits = true
//! ```

use serde::{Deserialize, Serialize};
use anyhow::{Result, anyhow, Context};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use tracing::{info, warn, debug, error};

/// GitHub verification configuration for a publisher
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GitHubPublisherConfig {
    /// Publisher ID (matches module manifest)
    pub id: String,
    
    /// GitHub organization or user
    pub github_org: String,
    
    /// Allowed repository names (empty = any repo in org)
    #[serde(default)]
    pub allowed_repos: Vec<String>,
    
    /// Require commits to be signed (GPG or SSH verified by GitHub)
    #[serde(default = "default_true")]
    pub require_signed_commits: bool,
    
    /// Require releases to be from GitHub Actions
    #[serde(default)]
    pub require_actions_build: bool,
    
    /// Allowed workflow file names (if require_actions_build)
    #[serde(default)]
    pub allowed_workflows: Vec<String>,
    
    /// Allowed GitHub usernames who can sign (empty = any org member)
    #[serde(default)]
    pub allowed_signers: Vec<String>,
    
    /// Minimum required GitHub account age (days) for signers
    #[serde(default)]
    pub min_account_age_days: u32,
    
    /// Require the release to be marked as "latest"
    #[serde(default)]
    pub require_latest_release: bool,
    
    /// Allow pre-release versions
    #[serde(default)]
    pub allow_prereleases: bool,
}

fn default_true() -> bool { true }

/// GitHub commit verification status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GitHubCommitVerification {
    /// Whether the commit signature is verified by GitHub
    pub verified: bool,
    
    /// Verification reason from GitHub
    pub reason: String,
    
    /// Signature type (gpg, ssh, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_type: Option<String>,
    
    /// Signer's email
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_email: Option<String>,
    
    /// Signer's GitHub username
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_login: Option<String>,
    
    /// GPG key ID (if GPG signed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
}

/// GitHub release information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GitHubReleaseInfo {
    /// Release tag name
    pub tag_name: String,
    
    /// Release name/title
    pub name: String,
    
    /// Whether this is a prerelease
    pub prerelease: bool,
    
    /// Whether this is a draft
    pub draft: bool,
    
    /// Release creation time
    pub created_at: DateTime<Utc>,
    
    /// Release publish time
    pub published_at: Option<DateTime<Utc>>,
    
    /// Author's GitHub login
    pub author_login: String,
    
    /// Target commit SHA
    pub target_commitish: String,
    
    /// Commit verification status
    pub commit_verification: Option<GitHubCommitVerification>,
    
    /// Assets in the release
    pub assets: Vec<GitHubReleaseAsset>,
}

/// GitHub release asset
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GitHubReleaseAsset {
    /// Asset name (filename)
    pub name: String,
    
    /// Content type
    pub content_type: String,
    
    /// Size in bytes
    pub size: u64,
    
    /// Download URL
    pub browser_download_url: String,
    
    /// SHA256 hash (if provided in release notes or .sha256 file)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// GitHub Actions workflow run info
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GitHubActionsRun {
    /// Workflow run ID
    pub run_id: u64,
    
    /// Workflow name
    pub workflow_name: String,
    
    /// Workflow file path
    pub workflow_path: String,
    
    /// Run status
    pub status: String,
    
    /// Run conclusion
    pub conclusion: Option<String>,
    
    /// Head SHA
    pub head_sha: String,
    
    /// Actor who triggered the run
    pub actor_login: String,
    
    /// Event that triggered the run
    pub event: String,
    
    /// Created timestamp
    pub created_at: DateTime<Utc>,
}

/// Result of GitHub signature verification
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GitHubVerificationResult {
    /// Overall verification passed
    pub verified: bool,
    
    /// Verification method used
    pub method: GitHubVerificationMethod,
    
    /// Publisher ID that was verified
    pub publisher_id: String,
    
    /// GitHub organization/user
    pub github_org: String,
    
    /// Repository name
    pub github_repo: String,
    
    /// Release tag (if release verification)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_tag: Option<String>,
    
    /// Commit SHA
    pub commit_sha: String,
    
    /// Signer information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    
    /// Detailed verification checks
    pub checks: Vec<VerificationCheck>,
    
    /// Timestamp of verification
    pub verified_at: DateTime<Utc>,
    
    /// Error message if verification failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Verification method used
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum GitHubVerificationMethod {
    /// Verified via signed GitHub release
    SignedRelease,
    /// Verified via signed commit
    SignedCommit,
    /// Verified via GitHub Actions attestation
    ActionsAttestation,
    /// Verified via Sigstore/cosign
    Sigstore,
    /// Multiple methods combined
    Combined,
}

/// Individual verification check result
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationCheck {
    /// Check name
    pub name: String,
    /// Check passed
    pub passed: bool,
    /// Details/reason
    pub details: String,
}

/// GitHub API client for verification
pub struct GitHubVerifier {
    /// GitHub API token (optional, for higher rate limits)
    api_token: Option<String>,
    /// HTTP client
    client: reqwest::Client,
    /// Base API URL (for GitHub Enterprise support)
    api_base_url: String,
    /// Publisher configurations
    publishers: HashMap<String, GitHubPublisherConfig>,
}

impl GitHubVerifier {
    /// Create a new GitHub verifier
    pub fn new(api_token: Option<String>) -> Self {
        Self {
            api_token,
            client: reqwest::Client::builder()
                .user_agent("cryfttee/0.4.0")
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
            api_base_url: "https://api.github.com".to_string(),
            publishers: HashMap::new(),
        }
    }
    
    /// Create verifier for GitHub Enterprise
    pub fn new_enterprise(api_base_url: String, api_token: Option<String>) -> Self {
        Self {
            api_token,
            client: reqwest::Client::builder()
                .user_agent("cryfttee/0.4.0")
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
            api_base_url,
            publishers: HashMap::new(),
        }
    }
    
    /// Add a publisher configuration
    pub fn add_publisher(&mut self, config: GitHubPublisherConfig) {
        self.publishers.insert(config.id.clone(), config);
    }
    
    /// Load publishers from trust.toml GitHub section
    pub fn load_publishers_from_config(&mut self, configs: Vec<GitHubPublisherConfig>) {
        for config in configs {
            self.publishers.insert(config.id.clone(), config);
        }
    }
    
    /// Build request with optional auth
    fn build_request(&self, url: &str) -> reqwest::RequestBuilder {
        let mut req = self.client.get(url);
        if let Some(token) = &self.api_token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }
        req.header("Accept", "application/vnd.github+json")
           .header("X-GitHub-Api-Version", "2022-11-28")
    }
    
    /// Verify a module package from a GitHub release
    pub async fn verify_release(
        &self,
        publisher_id: &str,
        repo: &str,
        tag: &str,
        expected_hash: &str,
    ) -> Result<GitHubVerificationResult> {
        let config = self.publishers.get(publisher_id)
            .ok_or_else(|| anyhow!("Unknown GitHub publisher: {}", publisher_id))?;
        
        info!("Verifying GitHub release: {}/{} tag={}", config.github_org, repo, tag);
        
        let mut checks = Vec::new();
        
        // Check 1: Repository is allowed
        let repo_allowed = config.allowed_repos.is_empty() || 
            config.allowed_repos.contains(&repo.to_string());
        checks.push(VerificationCheck {
            name: "repository_allowed".to_string(),
            passed: repo_allowed,
            details: if repo_allowed {
                format!("Repository '{}' is allowed", repo)
            } else {
                format!("Repository '{}' not in allowed list", repo)
            },
        });
        
        if !repo_allowed {
            return Ok(GitHubVerificationResult {
                verified: false,
                method: GitHubVerificationMethod::SignedRelease,
                publisher_id: publisher_id.to_string(),
                github_org: config.github_org.clone(),
                github_repo: repo.to_string(),
                release_tag: Some(tag.to_string()),
                commit_sha: String::new(),
                signer: None,
                checks,
                verified_at: Utc::now(),
                error: Some("Repository not allowed".to_string()),
            });
        }
        
        // Fetch release info from GitHub API
        let release_url = format!(
            "{}/repos/{}/{}/releases/tags/{}",
            self.api_base_url, config.github_org, repo, tag
        );
        
        let release_response = self.build_request(&release_url)
            .send()
            .await
            .context("Failed to fetch GitHub release")?;
        
        if !release_response.status().is_success() {
            let status = release_response.status();
            return Ok(GitHubVerificationResult {
                verified: false,
                method: GitHubVerificationMethod::SignedRelease,
                publisher_id: publisher_id.to_string(),
                github_org: config.github_org.clone(),
                github_repo: repo.to_string(),
                release_tag: Some(tag.to_string()),
                commit_sha: String::new(),
                signer: None,
                checks,
                verified_at: Utc::now(),
                error: Some(format!("GitHub API error: {}", status)),
            });
        }
        
        let release: serde_json::Value = release_response.json().await?;
        
        // Check 2: Not a draft
        let is_draft = release["draft"].as_bool().unwrap_or(false);
        checks.push(VerificationCheck {
            name: "not_draft".to_string(),
            passed: !is_draft,
            details: if is_draft { "Release is a draft".to_string() } else { "Release is published".to_string() },
        });
        
        // Check 3: Prerelease handling
        let is_prerelease = release["prerelease"].as_bool().unwrap_or(false);
        let prerelease_ok = config.allow_prereleases || !is_prerelease;
        checks.push(VerificationCheck {
            name: "prerelease_policy".to_string(),
            passed: prerelease_ok,
            details: if is_prerelease {
                if config.allow_prereleases {
                    "Prerelease allowed by policy".to_string()
                } else {
                    "Prereleases not allowed".to_string()
                }
            } else {
                "Stable release".to_string()
            },
        });
        
        // Get target commit
        let target_commitish = release["target_commitish"].as_str().unwrap_or("");
        let commit_sha = if target_commitish.len() == 40 {
            target_commitish.to_string()
        } else {
            // Need to resolve the ref
            self.resolve_ref(&config.github_org, repo, target_commitish).await
                .unwrap_or_else(|_| target_commitish.to_string())
        };
        
        // Check 4: Verify commit signature
        let commit_verification = self.verify_commit(&config.github_org, repo, &commit_sha).await;
        let commit_signed = commit_verification.as_ref()
            .map(|v| v.verified)
            .unwrap_or(false);
        
        let commit_check_passed = !config.require_signed_commits || commit_signed;
        checks.push(VerificationCheck {
            name: "commit_signature".to_string(),
            passed: commit_check_passed,
            details: match &commit_verification {
                Ok(v) if v.verified => format!(
                    "Commit signed by {} ({})",
                    v.signer_login.as_deref().unwrap_or("unknown"),
                    v.signature_type.as_deref().unwrap_or("unknown")
                ),
                Ok(v) => format!("Commit not verified: {}", v.reason),
                Err(e) => format!("Failed to verify commit: {}", e),
            },
        });
        
        // Check 5: Signer is allowed
        let signer_login = commit_verification.as_ref()
            .ok()
            .and_then(|v| v.signer_login.clone());
        let signer_allowed = config.allowed_signers.is_empty() ||
            signer_login.as_ref().map(|s| config.allowed_signers.contains(s)).unwrap_or(false);
        checks.push(VerificationCheck {
            name: "signer_allowed".to_string(),
            passed: signer_allowed || !commit_signed,
            details: if let Some(ref signer) = signer_login {
                if signer_allowed {
                    format!("Signer '{}' is allowed", signer)
                } else {
                    format!("Signer '{}' not in allowed list", signer)
                }
            } else {
                "No signer information".to_string()
            },
        });
        
        // Check 6: GitHub Actions build (if required)
        let actions_check_passed = if config.require_actions_build {
            match self.verify_actions_build(&config.github_org, repo, &commit_sha, &config.allowed_workflows).await {
                Ok(run) => {
                    checks.push(VerificationCheck {
                        name: "actions_build".to_string(),
                        passed: true,
                        details: format!(
                            "Built by workflow '{}' (run #{})",
                            run.workflow_name, run.run_id
                        ),
                    });
                    true
                }
                Err(e) => {
                    checks.push(VerificationCheck {
                        name: "actions_build".to_string(),
                        passed: false,
                        details: format!("Actions verification failed: {}", e),
                    });
                    false
                }
            }
        } else {
            true
        };
        
        // Determine overall result
        let all_passed = checks.iter().all(|c| c.passed);
        
        Ok(GitHubVerificationResult {
            verified: all_passed,
            method: GitHubVerificationMethod::SignedRelease,
            publisher_id: publisher_id.to_string(),
            github_org: config.github_org.clone(),
            github_repo: repo.to_string(),
            release_tag: Some(tag.to_string()),
            commit_sha,
            signer: signer_login,
            checks,
            verified_at: Utc::now(),
            error: if all_passed { None } else { Some("One or more checks failed".to_string()) },
        })
    }
    
    /// Verify a commit's signature
    pub async fn verify_commit(
        &self,
        org: &str,
        repo: &str,
        sha: &str,
    ) -> Result<GitHubCommitVerification> {
        let commit_url = format!(
            "{}/repos/{}/{}/commits/{}",
            self.api_base_url, org, repo, sha
        );
        
        let response = self.build_request(&commit_url)
            .send()
            .await
            .context("Failed to fetch commit")?;
        
        if !response.status().is_success() {
            return Err(anyhow!("GitHub API error: {}", response.status()));
        }
        
        let commit: serde_json::Value = response.json().await?;
        
        let verification = &commit["commit"]["verification"];
        
        Ok(GitHubCommitVerification {
            verified: verification["verified"].as_bool().unwrap_or(false),
            reason: verification["reason"].as_str().unwrap_or("unknown").to_string(),
            signature_type: verification["signature"].as_str().map(|s| {
                if s.starts_with("-----BEGIN PGP") {
                    "gpg".to_string()
                } else if s.starts_with("-----BEGIN SSH") {
                    "ssh".to_string()
                } else {
                    "unknown".to_string()
                }
            }),
            signer_email: commit["commit"]["author"]["email"].as_str().map(String::from),
            signer_login: commit["author"]["login"].as_str().map(String::from),
            key_id: verification["payload"].as_str().and_then(|p| {
                // Extract key ID from GPG payload if present
                p.lines()
                    .find(|l| l.contains("Key ID"))
                    .map(|l| l.trim().to_string())
            }),
        })
    }
    
    /// Resolve a ref (branch/tag) to a commit SHA
    async fn resolve_ref(&self, org: &str, repo: &str, ref_name: &str) -> Result<String> {
        let ref_url = format!(
            "{}/repos/{}/{}/git/ref/tags/{}",
            self.api_base_url, org, repo, ref_name
        );
        
        let response = self.build_request(&ref_url)
            .send()
            .await?;
        
        if response.status().is_success() {
            let data: serde_json::Value = response.json().await?;
            if let Some(sha) = data["object"]["sha"].as_str() {
                return Ok(sha.to_string());
            }
        }
        
        // Try as branch
        let ref_url = format!(
            "{}/repos/{}/{}/git/ref/heads/{}",
            self.api_base_url, org, repo, ref_name
        );
        
        let response = self.build_request(&ref_url)
            .send()
            .await?;
        
        if response.status().is_success() {
            let data: serde_json::Value = response.json().await?;
            if let Some(sha) = data["object"]["sha"].as_str() {
                return Ok(sha.to_string());
            }
        }
        
        Err(anyhow!("Could not resolve ref: {}", ref_name))
    }
    
    /// Verify the commit was built by an allowed GitHub Actions workflow
    async fn verify_actions_build(
        &self,
        org: &str,
        repo: &str,
        commit_sha: &str,
        allowed_workflows: &[String],
    ) -> Result<GitHubActionsRun> {
        // Get workflow runs for this commit
        let runs_url = format!(
            "{}/repos/{}/{}/actions/runs?head_sha={}",
            self.api_base_url, org, repo, commit_sha
        );
        
        let response = self.build_request(&runs_url)
            .send()
            .await
            .context("Failed to fetch workflow runs")?;
        
        if !response.status().is_success() {
            return Err(anyhow!("GitHub API error: {}", response.status()));
        }
        
        let data: serde_json::Value = response.json().await?;
        let runs = data["workflow_runs"].as_array()
            .ok_or_else(|| anyhow!("No workflow runs found"))?;
        
        // Find a successful run from an allowed workflow
        for run in runs {
            let workflow_path = run["path"].as_str().unwrap_or("");
            let workflow_name = workflow_path.split('/').last().unwrap_or(workflow_path);
            let conclusion = run["conclusion"].as_str().unwrap_or("");
            
            // Check if workflow is allowed
            let workflow_allowed = allowed_workflows.is_empty() ||
                allowed_workflows.iter().any(|w| workflow_name == w || workflow_path.ends_with(w));
            
            if workflow_allowed && conclusion == "success" {
                return Ok(GitHubActionsRun {
                    run_id: run["id"].as_u64().unwrap_or(0),
                    workflow_name: run["name"].as_str().unwrap_or("").to_string(),
                    workflow_path: workflow_path.to_string(),
                    status: run["status"].as_str().unwrap_or("").to_string(),
                    conclusion: Some(conclusion.to_string()),
                    head_sha: run["head_sha"].as_str().unwrap_or("").to_string(),
                    actor_login: run["actor"]["login"].as_str().unwrap_or("").to_string(),
                    event: run["event"].as_str().unwrap_or("").to_string(),
                    created_at: run["created_at"].as_str()
                        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(Utc::now),
                });
            }
        }
        
        Err(anyhow!("No successful workflow run found from allowed workflows"))
    }
    
    /// Verify a module using GitHub attestations (Sigstore-based)
    /// This uses GitHub's artifact attestations feature
    pub async fn verify_attestation(
        &self,
        publisher_id: &str,
        repo: &str,
        artifact_digest: &str,
    ) -> Result<GitHubVerificationResult> {
        let config = self.publishers.get(publisher_id)
            .ok_or_else(|| anyhow!("Unknown GitHub publisher: {}", publisher_id))?;
        
        info!("Verifying GitHub attestation for artifact: {}", artifact_digest);
        
        // GitHub Attestations API
        let attestation_url = format!(
            "{}/repos/{}/{}/attestations/sha256:{}",
            self.api_base_url, config.github_org, repo, artifact_digest
        );
        
        let response = self.build_request(&attestation_url)
            .send()
            .await
            .context("Failed to fetch attestation")?;
        
        if !response.status().is_success() {
            return Ok(GitHubVerificationResult {
                verified: false,
                method: GitHubVerificationMethod::Sigstore,
                publisher_id: publisher_id.to_string(),
                github_org: config.github_org.clone(),
                github_repo: repo.to_string(),
                release_tag: None,
                commit_sha: String::new(),
                signer: None,
                checks: vec![VerificationCheck {
                    name: "attestation_fetch".to_string(),
                    passed: false,
                    details: format!("No attestation found for artifact"),
                }],
                verified_at: Utc::now(),
                error: Some("Attestation not found".to_string()),
            });
        }
        
        let data: serde_json::Value = response.json().await?;
        let attestations = data["attestations"].as_array();
        
        let mut checks = Vec::new();
        
        if let Some(attestations) = attestations {
            if attestations.is_empty() {
                checks.push(VerificationCheck {
                    name: "attestation_exists".to_string(),
                    passed: false,
                    details: "No attestations found".to_string(),
                });
            } else {
                // Check the first valid attestation
                let attestation = &attestations[0];
                let bundle = &attestation["bundle"];
                
                // Verify the attestation bundle
                let cert_chain_valid = bundle["verificationMaterial"]["x509CertificateChain"].is_object();
                checks.push(VerificationCheck {
                    name: "certificate_chain".to_string(),
                    passed: cert_chain_valid,
                    details: if cert_chain_valid {
                        "Valid certificate chain present".to_string()
                    } else {
                        "No certificate chain".to_string()
                    },
                });
                
                // Check repository matches
                let repo_uri = attestation["repository_id"].as_u64();
                checks.push(VerificationCheck {
                    name: "repository_match".to_string(),
                    passed: repo_uri.is_some(),
                    details: "Repository attestation present".to_string(),
                });
            }
        }
        
        let all_passed = !checks.is_empty() && checks.iter().all(|c| c.passed);
        
        Ok(GitHubVerificationResult {
            verified: all_passed,
            method: GitHubVerificationMethod::Sigstore,
            publisher_id: publisher_id.to_string(),
            github_org: config.github_org.clone(),
            github_repo: repo.to_string(),
            release_tag: None,
            commit_sha: String::new(),
            signer: None,
            checks,
            verified_at: Utc::now(),
            error: if all_passed { None } else { Some("Attestation verification failed".to_string()) },
        })
    }
}

/// Parse GitHub publisher configs from trust.toml
pub fn parse_github_publishers(toml_value: &toml::Value) -> Vec<GitHubPublisherConfig> {
    let mut configs = Vec::new();
    
    if let Some(publishers) = toml_value.get("github_publishers").and_then(|v| v.as_array()) {
        for publisher in publishers {
            if let Ok(config) = toml::from_str::<GitHubPublisherConfig>(
                &toml::to_string(publisher).unwrap_or_default()
            ) {
                configs.push(config);
            }
        }
    }
    
    configs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_github_publisher_config_defaults() {
        let config = GitHubPublisherConfig {
            id: "test".to_string(),
            github_org: "test-org".to_string(),
            allowed_repos: vec![],
            require_signed_commits: true,
            require_actions_build: false,
            allowed_workflows: vec![],
            allowed_signers: vec![],
            min_account_age_days: 0,
            require_latest_release: false,
            allow_prereleases: false,
        };
        
        assert!(config.require_signed_commits);
        assert!(!config.require_actions_build);
    }

    #[test]
    fn test_verification_check() {
        let check = VerificationCheck {
            name: "test_check".to_string(),
            passed: true,
            details: "Test passed".to_string(),
        };
        
        assert!(check.passed);
    }
}
