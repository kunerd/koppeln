use std::process::Command;
use std::thread;
use std::time::Duration;

use names::Generator;

use test_helper::linux_containers::{LxcContainer, LxcContainerError};

struct TestContainer {
    image_name: String,
}

impl TestContainer {
    pub fn new(image_name: String) -> TestContainer {
        TestContainer { image_name }
    }

    pub fn with<F: FnOnce(&mut LxcContainer) -> Result<(), LxcContainerError>>(&self, func: F) -> Result<(), LxcContainerError> {
        let mut generator = Generator::default();
        let container_name = generator.next().unwrap();

        let mut container = LxcContainer::launch(&self.image_name, container_name.into())?;

        func(&mut container)?;
        
        container.stop()?;
        container.delete()
    }
}

#[test]
fn test_container_launch_and_stop() -> Result<(), LxcContainerError> {
    TestContainer::new("debian/buster".into()).with(|c| {
        thread::sleep(Duration::from_millis(5000));

        let stdout = Command::new("lxc")
            .arg("list")
            .args(["--columns", "s"])
            .args(["--format", "csv"])
            .arg("status=running")
            .arg(format!("{}$", c.name))
            .output()
            .unwrap()
            .stdout;

        let stdout = String::from_utf8(stdout).unwrap();

        assert!(stdout.contains("RUNNING"));

        Ok(())
    })
}

#[test]
fn test_container_ips() -> Result<(), LxcContainerError> {
    TestContainer::new("debian/buster".into()).with(|c| {
        thread::sleep(Duration::from_millis(5000));

        let ips = c.get_ips()?;

        assert!(ips.len() > 0);

        Ok(())
    })
}
