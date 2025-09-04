use axum::{
    extract::{ConnectInfo, Request},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Clone)]
pub struct RateLimiter {
    store: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    max_requests: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            store: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window,
        }
    }

    pub fn is_allowed(&self, key: &str) -> bool {
        let mut store = self.store.lock().unwrap();
        let now = Instant::now();
        
        let requests = store.entry(key.to_string()).or_insert_with(Vec::new);
        
        requests.retain(|&timestamp| now.duration_since(timestamp) < self.window);
        
        if requests.len() < self.max_requests {
            requests.push(now);
            true
        } else {
            false
        }
    }
}

pub async fn rate_limit_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    static RATE_LIMITER: std::sync::OnceLock<RateLimiter> = std::sync::OnceLock::new();
    let limiter = RATE_LIMITER.get_or_init(|| RateLimiter::new(5, Duration::from_secs(300)));
    
    let client_ip = addr.ip().to_string();
    
    if !limiter.is_allowed(&client_ip) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    
    Ok(next.run(request).await)
}
