use std::process::Command;

fn main() {
    // Version precedence:
    // 1. RELEASE_VERSION env var (set by release script for container builds)
    // 2. git describe with proper semver tags only (vX.Y.Z, not vX.Y.Z-suffix)
    // 3. 0.0.0-g<hash> for repos without semver tags
    // 4. Cargo.toml version (final fallback)
    let version = std::env::var("RELEASE_VERSION")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            // Try git describe with only proper semver tags (exclude -suffix tags)
            let describe = Command::new("git")
                .args([
                    "describe",
                    "--tags",
                    "--match",
                    "v[0-9]*",
                    "--exclude",
                    "*-*",
                    "--always",
                ])
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());

            match describe {
                Some(ref s) if s.starts_with('v') => {
                    // Has a semver tag: v0.1.0-3-gabcdef -> 0.1.0-3-gabcdef
                    Some(s.trim_start_matches('v').to_string())
                }
                Some(hash) => {
                    // Just a commit hash (no semver tags): use 0.0.0-g<hash>
                    Some(format!("0.0.0-g{}", hash))
                }
                None => None,
            }
        })
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());

    println!("cargo:rustc-env=KAHL_VERSION={}", version);
    println!("cargo:rerun-if-env-changed=RELEASE_VERSION");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/tags");
}
