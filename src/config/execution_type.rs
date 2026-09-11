use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub enum ExecutionType {
    Auto,
    #[default]
    Assisted,
}

impl std::fmt::Display for ExecutionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecutionType::Auto => write!(f, "Automático"),
            ExecutionType::Assisted => write!(f, "Assistido"),
        }
    }
}
