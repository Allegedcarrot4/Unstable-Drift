use std::collections::HashMap;
use std::sync::Mutex;
use tokio::time::Instant;

use crate::handle::IoStream;

const MAX_PER_HOST: usize = 4;
const IDLE_TIMEOUT_SECS: u64 = 30;

struct PooledConnection {
    stream: Box<dyn IoStream>,
    expires_at: Instant,
}

pub struct ConnectionPool {
    inner: Mutex<HashMap<(String, u16), Vec<PooledConnection>>>,
}

impl ConnectionPool {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn get(&self, host: &str, port: u16) -> Option<Box<dyn IoStream>> {
        let mut map = self.inner.lock().unwrap();
        let key = (host.to_string(), port);
        let connections = map.get_mut(&key)?;
        let now = Instant::now();
        connections.retain(|c| c.expires_at > now);
        let stream = connections.pop().map(|c| c.stream);
        if connections.is_empty() {
            map.remove(&key);
        }
        stream
    }

    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn put(&self, host: &str, port: u16, stream: Box<dyn IoStream>) {
        let mut map = self.inner.lock().unwrap();
        let key = (host.to_string(), port);
        let connections = map.entry(key).or_default();
        if connections.len() < MAX_PER_HOST {
            connections.push(PooledConnection {
                stream,
                expires_at: Instant::now() + std::time::Duration::from_secs(IDLE_TIMEOUT_SECS),
            });
        }
    }

    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn cleanup(&self) {
        let mut map = self.inner.lock().unwrap();
        let now = Instant::now();
        map.retain(|_, connections| {
            connections.retain(|c| c.expires_at > now);
            !connections.is_empty()
        });
    }
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}
