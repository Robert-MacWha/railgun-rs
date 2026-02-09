// In tests/common/mod.rs or a fixture
use std::{
    process::{Child, Command, Stdio},
    time::Duration,
};

use tokio::time::sleep;

pub struct AnvilInstance {
    child: Child,
}

const FORK_PORT: &str = "8545";

impl AnvilInstance {
    pub async fn fork_with_state(fork_url: &str, block: u64, state_path: &str) -> Self {
        let child = Command::new("anvil")
            .args([
                "--fork-url",
                fork_url,
                "--fork-block-number",
                &block.to_string(),
                "--load-state",
                state_path,
                "--port",
                FORK_PORT,
            ])
            .spawn()
            .expect("anvil not found");
        sleep(Duration::from_secs(1)).await;
        Self { child }
    }
}

impl Drop for AnvilInstance {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}
