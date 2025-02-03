pub static FOUNDATION_VERSION: &str = env!("CARGO_PKG_VERSION");

use std::cmp::Ordering;
use std::fmt;
use std::num::ParseIntError;

#[derive(Debug, PartialEq, Eq)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl Version {
    pub fn new(major: u64, minor: u64, patch: u64) -> Self {
        Version {
            major,
            minor,
            patch,
        }
    }

    pub fn parse(version_str: &str) -> Result<Self, ParseIntError> {
        let parts: Vec<&str> = version_str.split('.').collect();
        let major = parts.first().unwrap_or(&"0").parse::<u64>()?;
        let minor = parts.get(1).unwrap_or(&"0").parse::<u64>()?;
        let patch = parts.get(2).unwrap_or(&"0").parse::<u64>()?;
        Ok(Version::new(major, minor, patch))
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.major
            .cmp(&other.major)
            .then_with(|| self.minor.cmp(&other.minor))
            .then_with(|| self.patch.cmp(&other.patch))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}
