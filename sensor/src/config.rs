use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
pub struct SensorConfig {
    pub server: String,
    pub cert: PathBuf,
    pub key: PathBuf,
    pub ca: PathBuf,
    pub interface: String,
    #[serde(default = "default_buffer_size")]
    pub buffer_size_mb: usize,
}

fn default_buffer_size() -> usize {
    100
}

impl SensorConfig {
    pub fn from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: SensorConfig = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    pub fn buffer_size_bytes(&self) -> usize {
        self.buffer_size_mb * 1024 * 1024
    }
}
