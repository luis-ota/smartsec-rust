use async_trait::async_trait;

#[async_trait]
#[allow(dead_code)]
pub trait SandboxManager: Send + Sync {
    fn is_available(&self) -> bool;
    async fn prepare(&self) -> Result<(), anyhow::Error>;
    async fn cleanup(&self) -> Result<(), anyhow::Error>;
}

#[allow(dead_code)]
pub struct LocalSandbox;

#[async_trait]
impl SandboxManager for LocalSandbox {
    fn is_available(&self) -> bool {
        true
    }

    async fn prepare(&self) -> Result<(), anyhow::Error> {
        Ok(())
    }

    async fn cleanup(&self) -> Result<(), anyhow::Error> {
        Ok(())
    }
}

#[allow(dead_code)]
pub struct MockSandbox;

#[async_trait]
impl SandboxManager for MockSandbox {
    fn is_available(&self) -> bool {
        true
    }

    async fn prepare(&self) -> Result<(), anyhow::Error> {
        Ok(())
    }

    async fn cleanup(&self) -> Result<(), anyhow::Error> {
        Ok(())
    }
}
