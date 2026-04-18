// Copyright (c) 2026 Kantoshi Miyamura

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum ThreatLevel {
    Safe = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl ThreatLevel {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Safe => "SAFE",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }

    pub fn color(&self) -> &'static str {
        match self {
            Self::Safe => "#4caf7d",
            Self::Low => "#8bc34a",
            Self::Medium => "#faad14",
            Self::High => "#ff9800",
            Self::Critical => "#f44336",
        }
    }

    pub fn emoji(&self) -> &'static str {
        match self {
            Self::Safe => "🟢",
            Self::Low => "🟡",
            Self::Medium => "🟠",
            Self::High => "🔴",
            Self::Critical => "🚨",
        }
    }
}

impl std::fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threat_level_ordering() {
        assert!(ThreatLevel::Safe < ThreatLevel::Low);
        assert!(ThreatLevel::Low < ThreatLevel::Medium);
        assert!(ThreatLevel::Medium < ThreatLevel::High);
        assert!(ThreatLevel::High < ThreatLevel::Critical);
    }

    #[test]
    fn threat_level_display() {
        assert_eq!(ThreatLevel::Safe.to_string(), "SAFE");
        assert_eq!(ThreatLevel::Critical.to_string(), "CRITICAL");
    }
}
