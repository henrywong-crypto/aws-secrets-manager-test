use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

pub struct AppError(pub StatusCode, pub String);

impl AppError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self(status, message.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.0, self.1).into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        let _err: anyhow::Error = err.into();
        tracing::error!("internal error handling request");
        Self(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal server error".to_string(),
        )
    }
}
