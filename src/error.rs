use core::fmt;
use std::error::Error;

pub type Result<T> = std::result::Result<T, TracingPerfettoError>;

#[derive(Debug)]
pub struct TracingPerfettoError {
    message: String,
    source: Option<Box<dyn Error>>,
}

impl TracingPerfettoError {
    pub(crate) fn new(message: &str, source: Box<dyn Error>) -> Self {
        Self {
            message: message.to_string(),
            source: Some(source),
        }
    }
}

// `Error` トレイトを実装
impl Error for TracingPerfettoError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source.as_deref()
    }
}

// `Display` トレイトを実装
impl fmt::Display for TracingPerfettoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)?;
        if let Some(source) = &self.source {
            write!(f, ": {}", source)?;
        }
        Ok(())
    }
}
