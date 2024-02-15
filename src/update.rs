
// For config files pulled from the backend
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum UpdateStatus {
    Updated,
    NotUpdated,
    FormatError,
}