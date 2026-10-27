use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ScopeError {
    #[error("Research mode requires explicit project owner opt-in")]
    OwnerOptInRequired,

    #[error("Target root does not exist: {0}")]
    TargetNotFound(PathBuf),

    #[error("Target root is not a directory: {0}")]
    NotADirectory(PathBuf),

    #[error("Path '{path}' escapes authorized root '{root}'")]
    OutsideRoot { path: PathBuf, root: PathBuf },

    #[error("Symlink '{symlink}' escapes authorized root by pointing to '{target}'")]
    SymlinkEscape { symlink: PathBuf, target: PathBuf },

    #[error("Path '{path}' is explicitly excluded or not within allowed subpaths")]
    PathExcluded { path: PathBuf },

    #[error("Failed to inspect filesystem metadata for '{path}': {message}")]
    IoError { path: PathBuf, message: String },
}

/// Defines and enforces the immutable boundary of authorized research and analysis targets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResearchScope {
    /// Canonicalized absolute root path of the target workspace
    pub target_root: PathBuf,
    /// Explicit allowed subpaths within the target root (empty means entire target_root allowed)
    pub allowed_subpaths: Vec<PathBuf>,
    /// Explicit excluded subpaths (e.g. .git, node_modules)
    pub excluded_subpaths: Vec<PathBuf>,
    /// Explicit project owner authorization to run research experiments
    pub owner_opt_in: bool,
    /// Optional authorization ticket or grant reference
    pub authorization_ref: Option<String>,
}

impl ResearchScope {
    /// Creates a new `ResearchScope` verifying root existence, directory status, canonicalization,
    /// and project owner opt-in.
    pub fn new(target_root: impl AsRef<Path>, owner_opt_in: bool) -> Result<Self, ScopeError> {
        let raw_path = target_root.as_ref();
        if !raw_path.exists() {
            return Err(ScopeError::TargetNotFound(raw_path.to_path_buf()));
        }

        let canonical_root = fs::canonicalize(raw_path).map_err(|e| ScopeError::IoError {
            path: raw_path.to_path_buf(),
            message: e.to_string(),
        })?;

        if !canonical_root.is_dir() {
            return Err(ScopeError::NotADirectory(canonical_root));
        }

        if !owner_opt_in {
            return Err(ScopeError::OwnerOptInRequired);
        }

        let default_excluded = vec![
            canonical_root.join(".git"),
            canonical_root.join("node_modules"),
            canonical_root.join("target"),
            canonical_root.join("dist"),
            canonical_root.join("build"),
            canonical_root.join(".aegis"),
            canonical_root.join(".cache"),
        ];

        Ok(Self {
            target_root: canonical_root,
            allowed_subpaths: Vec::new(),
            excluded_subpaths: default_excluded,
            owner_opt_in: true,
            authorization_ref: None,
        })
    }

    /// Sets explicit allowed subpaths within the target root.
    pub fn with_allowed_subpaths(mut self, subpaths: Vec<PathBuf>) -> Self {
        self.allowed_subpaths = subpaths
            .into_iter()
            .map(|p| {
                if p.is_relative() {
                    self.target_root.join(p)
                } else {
                    p
                }
            })
            .map(|p| fs::canonicalize(&p).unwrap_or(p))
            .collect();
        self
    }

    /// Adds explicit excluded subpaths.
    pub fn with_excluded_subpaths(mut self, subpaths: Vec<PathBuf>) -> Self {
        for p in subpaths {
            let full = if p.is_relative() {
                self.target_root.join(p)
            } else {
                p
            };
            let can = fs::canonicalize(&full).unwrap_or(full);
            if !self.excluded_subpaths.contains(&can) {
                self.excluded_subpaths.push(can);
            }
        }
        self
    }

    /// Attaches an authorization ticket reference.
    pub fn with_authorization_ref(mut self, auth_ref: impl Into<String>) -> Self {
        self.authorization_ref = Some(auth_ref.into());
        self
    }

    /// Validates research invariants: must have owner_opt_in and target_root must exist.
    pub fn validate(&self) -> Result<(), ScopeError> {
        if !self.owner_opt_in {
            return Err(ScopeError::OwnerOptInRequired);
        }
        if !self.target_root.exists() {
            return Err(ScopeError::TargetNotFound(self.target_root.clone()));
        }
        if !self.target_root.is_dir() {
            return Err(ScopeError::NotADirectory(self.target_root.clone()));
        }
        Ok(())
    }

    /// Determines if a target path is strictly within authorized scope, denying outside-root traversals
    /// and symlinks resolving outside the root boundary.
    pub fn is_path_in_scope(&self, path: &Path) -> Result<PathBuf, ScopeError> {
        self.validate()?;

        // If path has a parent that exists, canonicalize the parent to resolve platform aliases (e.g. /var -> /private/var on macOS)
        let canonical_parent = if let Some(parent) = path.parent() {
            if parent.as_os_str().is_empty() || path.is_relative() {
                self.target_root.clone()
            } else if parent.exists() {
                fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf())
            } else {
                parent.to_path_buf()
            }
        } else {
            self.target_root.clone()
        };

        let file_name = path.file_name();
        let target_in_canonical_root = if let Some(name) = file_name {
            canonical_parent.join(name)
        } else {
            canonical_parent
        };

        // 1. Logical component normalization to prevent ".." directory traversal
        let mut normalized = if path.is_relative() {
            self.target_root.clone()
        } else {
            PathBuf::new()
        };

        for comp in path.components() {
            match comp {
                std::path::Component::ParentDir => {
                    if !normalized.pop()
                        || (path.is_relative() && !normalized.starts_with(&self.target_root))
                    {
                        return Err(ScopeError::OutsideRoot {
                            path: path.to_path_buf(),
                            root: self.target_root.clone(),
                        });
                    }
                }
                std::path::Component::Normal(c) => {
                    normalized.push(c);
                }
                std::path::Component::CurDir => {}
                std::path::Component::RootDir => {
                    normalized = PathBuf::from("/");
                }
                std::path::Component::Prefix(p) => {
                    normalized = PathBuf::from(p.as_os_str());
                }
            }
        }

        // Check if normalized or target_in_canonical_root starts with target_root
        let base_check = normalized.starts_with(&self.target_root)
            || target_in_canonical_root.starts_with(&self.target_root);

        if !base_check {
            return Err(ScopeError::OutsideRoot {
                path: path.to_path_buf(),
                root: self.target_root.clone(),
            });
        }

        // 2. Physical symlink check
        let symlink_path = if path.is_symlink() {
            Some(path)
        } else if target_in_canonical_root.is_symlink() {
            Some(target_in_canonical_root.as_path())
        } else {
            None
        };

        if let Some(symlink) = symlink_path {
            let symlink_target = fs::read_link(symlink).map_err(|e| ScopeError::IoError {
                path: symlink.to_path_buf(),
                message: e.to_string(),
            })?;

            let absolute_target = if symlink_target.is_relative() {
                symlink
                    .parent()
                    .unwrap_or(&self.target_root)
                    .join(&symlink_target)
            } else {
                symlink_target
            };

            let canonical_target =
                fs::canonicalize(&absolute_target).map_err(|e| ScopeError::IoError {
                    path: absolute_target.clone(),
                    message: e.to_string(),
                })?;

            if !canonical_target.starts_with(&self.target_root) {
                return Err(ScopeError::SymlinkEscape {
                    symlink: symlink.to_path_buf(),
                    target: canonical_target,
                });
            }
        }

        // 3. Final canonicalization if it exists on disk
        let check_path = if target_in_canonical_root.exists() {
            &target_in_canonical_root
        } else if normalized.exists() {
            &normalized
        } else {
            &target_in_canonical_root
        };

        let final_path = if check_path.exists() {
            let canonical = fs::canonicalize(check_path).map_err(|e| ScopeError::IoError {
                path: check_path.clone(),
                message: e.to_string(),
            })?;
            if !canonical.starts_with(&self.target_root) {
                if check_path.is_symlink() {
                    return Err(ScopeError::SymlinkEscape {
                        symlink: check_path.clone(),
                        target: canonical,
                    });
                } else {
                    return Err(ScopeError::OutsideRoot {
                        path: canonical,
                        root: self.target_root.clone(),
                    });
                }
            }
            canonical
        } else {
            target_in_canonical_root
        };

        // 4. Excluded subpaths check
        for excluded in &self.excluded_subpaths {
            if final_path.starts_with(excluded) {
                return Err(ScopeError::PathExcluded { path: final_path });
            }
        }

        // 5. Allowed subpaths check (if configured)
        if !self.allowed_subpaths.is_empty() {
            let within_allowed = self
                .allowed_subpaths
                .iter()
                .any(|allowed| final_path.starts_with(allowed));
            if !within_allowed {
                return Err(ScopeError::PathExcluded { path: final_path });
            }
        }

        Ok(final_path)
    }
}
