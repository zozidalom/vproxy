/// Auth Error
#[derive(thiserror::Error, Debug)]
pub enum AuthError {
    #[error("Missing credentials")]
    MissingCredentials,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Unauthorized")]
    Unauthorized,
}

/// Proxy Error
#[derive(thiserror::Error, Debug)]
pub enum ProxyError {
    /// Hyper Error
    #[error("{0:?}")]
    HyperError(#[from] hyper::Error),

    /// Hyper Legacy Error
    #[error("{0:?}")]
    HyperLegacyError(#[from] hyper_util::client::legacy::Error),

    /// Hyper HTTP Error
    #[error("{0:?}")]
    AuthError(#[from] AuthError),
}
