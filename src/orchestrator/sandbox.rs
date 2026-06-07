use async_trait::async_trait;

#[async_trait]
pub trait SandboxManager: Send + Sync {
    fn create_isolated_environment(&self, image_name: &str) -> Result<String, anyhow::Error>;

    fn run_command(&self, container_id: &str, command: &str) -> Result<String, anyhow::Error>;

    fn destroy_environment(&self, container_id: &str) -> Result<(), anyhow::Error>;
}

pub struct LocalSandbox;

#[async_trait]
#[allow(dead_code)]
impl SandboxManager for LocalSandbox {
    fn create_isolated_environment(&self, image_name: &str) -> Result<String, anyhow::Error> {
        Ok(format!(
            "local-{}",
            image_name.replace(':', "-").replace('/', "_")
        ))
    }

    fn run_command(&self, _container_id: &str, command: &str) -> Result<String, anyhow::Error> {
        Ok(format!("[local-sandbox] $ {}", command))
    }

    fn destroy_environment(&self, _container_id: &str) -> Result<(), anyhow::Error> {
        Ok(())
    }
}

pub struct MockSandbox;

#[async_trait]
impl SandboxManager for MockSandbox {
    fn create_isolated_environment(&self, image_name: &str) -> Result<String, anyhow::Error> {
        Ok(format!("mock-{}", image_name))
    }

    fn run_command(&self, container_id: &str, command: &str) -> Result<String, anyhow::Error> {
        Ok(format!("[mock-sandbox:{}] $ {}", container_id, command))
    }

    fn destroy_environment(&self, _container_id: &str) -> Result<(), anyhow::Error> {
        Ok(())
    }
}
