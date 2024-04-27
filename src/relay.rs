use crate::{
    error::Error,
    jsonrpc::{Request, Response},
};

use reqwest::Client;
use serde::{de::DeserializeOwned, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use url::Url;

#[derive(Debug)]
pub struct Relay {
    id: AtomicU64,
    client: Client,
    url: Url,
    user: Option<String>,
    pass: Option<String>,
}

impl Relay {
    /// Initializes a new relay client.
    pub fn new(url: impl Into<Url>, user: Option<String>, pass: Option<String>) -> Self {
        Self {
            id: AtomicU64::new(0),
            client: Client::new(),
            url: url.into(),
            user,
            pass,
        }
    }

    /// Sends a request with the provided method to the relay, with the
    /// parameters serialized as JSON.
    pub async fn request<T: Serialize + Send + Sync, R: DeserializeOwned>(
        &self,
        method: &str,
        params: T,
    ) -> Result<R, Error> {
        let next_id = self.id.load(Ordering::SeqCst) + 1;
        self.id.store(next_id, Ordering::SeqCst);

        let payload = Request::new(next_id, method, params);

        let mut req = self.client.post(self.url.as_ref());

        if let (Some(user), Some(pass)) = (&self.user, &self.pass) {
            req = req.basic_auth(user, Some(pass));
        }

        let res = req.json(&payload).send().await?;
        let status = res.error_for_status_ref();

        match status {
            Err(err) => {
                let text = res.text().await?;
                let status_code = err.status().unwrap();
                if status_code.is_client_error() {
                    // Client error (400-499)
                    Err(Error::ClientError { text })
                } else {
                    // Internal server error (500-599)
                    Err(Error::ServerError { text })
                }
            }
            Ok(_) => {
                let text = res.text().await?;
                let res: Response<R> = serde_json::from_str(&text)
                    .map_err(|err| Error::ResponseSerdeJson { err, text })?;

                Ok(res.data.into_result()?)
            }
        }
    }
}

impl Clone for Relay {
    fn clone(&self) -> Self {
        Self {
            id: AtomicU64::new(0),
            client: self.client.clone(),
            url: self.url.clone(),
            user: self.user.clone(),
            pass: self.pass.clone(),
        }
    }
}
