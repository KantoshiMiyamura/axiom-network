//! Role-based permission and authorization checks

use crate::error::{Result, ServerError};

/// User roles in the platform
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Role {
    Member,
    Worker,
    Verifier,
    Moderator,
    CoreDev,
}

impl Role {
    /// Parse role from string
    pub fn from_string(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "member" => Some(Role::Member),
            "worker" => Some(Role::Worker),
            "verifier" => Some(Role::Verifier),
            "moderator" => Some(Role::Moderator),
            "core_dev" => Some(Role::CoreDev),
            _ => None,
        }
    }

    /// Convert role to string
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Member => "member",
            Role::Worker => "worker",
            Role::Verifier => "verifier",
            Role::Moderator => "moderator",
            Role::CoreDev => "core_dev",
        }
    }

    /// Role hierarchy level (higher = more permissions)
    pub fn level(&self) -> u32 {
        match self {
            Role::Member => 1,
            Role::Worker => 2,
            Role::Verifier => 3,
            Role::Moderator => 4,
            Role::CoreDev => 5,
        }
    }
}

/// Parse roles from vector of strings
pub fn parse_roles(role_strings: &[String]) -> Vec<Role> {
    role_strings
        .iter()
        .filter_map(|s| Role::from_string(s))
        .collect()
}

/// Check if user has required role
pub fn has_role(roles: &[String], required: Role) -> bool {
    parse_roles(roles)
        .iter()
        .any(|r| r.level() >= required.level())
}

/// Check if user has specific role
pub fn has_specific_role(roles: &[String], role: Role) -> bool {
    parse_roles(roles).contains(&role)
}

/// Permission checks
pub fn check_can_post_message(roles: &[String]) -> Result<()> {
    if has_role(roles, Role::Member) {
        Ok(())
    } else {
        Err(ServerError::Shared(
            axiom_community_shared::Error::Unauthorized {
                required: "member".to_string(),
            },
        ))
    }
}

pub fn check_can_create_job(roles: &[String]) -> Result<()> {
    if has_role(roles, Role::Worker) {
        Ok(())
    } else {
        Err(ServerError::Shared(
            axiom_community_shared::Error::Unauthorized {
                required: "worker".to_string(),
            },
        ))
    }
}

pub fn check_can_file_dispute(roles: &[String]) -> Result<()> {
    if has_role(roles, Role::Verifier) {
        Ok(())
    } else {
        Err(ServerError::Shared(
            axiom_community_shared::Error::Unauthorized {
                required: "verifier".to_string(),
            },
        ))
    }
}

pub fn check_can_moderate(roles: &[String]) -> Result<()> {
    if has_role(roles, Role::Moderator) {
        Ok(())
    } else {
        Err(ServerError::Shared(
            axiom_community_shared::Error::Unauthorized {
                required: "moderator".to_string(),
            },
        ))
    }
}

pub fn check_can_view_audit(roles: &[String]) -> Result<()> {
    if has_role(roles, Role::CoreDev) {
        Ok(())
    } else {
        Err(ServerError::Shared(
            axiom_community_shared::Error::Unauthorized {
                required: "core_dev".to_string(),
            },
        ))
    }
}

pub fn check_can_manage_roles(roles: &[String]) -> Result<()> {
    if has_role(roles, Role::CoreDev) {
        Ok(())
    } else {
        Err(ServerError::Shared(
            axiom_community_shared::Error::Unauthorized {
                required: "core_dev".to_string(),
            },
        ))
    }
}

pub fn check_can_ban_user(roles: &[String]) -> Result<()> {
    if has_role(roles, Role::CoreDev) {
        Ok(())
    } else {
        Err(ServerError::Shared(
            axiom_community_shared::Error::Unauthorized {
                required: "core_dev".to_string(),
            },
        ))
    }
}
