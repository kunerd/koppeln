use names::Generator;

pub mod core;

pub  struct TestContainer {
    image_name: String,
}

impl TestContainer {
    pub fn new(image_name: String) -> TestContainer {
        TestContainer { image_name }
    }

    pub fn with<F: FnOnce(&mut core::LxcContainer) -> Result<(), core::LxcContainerError>>(&self, func: F) -> Result<(), core::LxcContainerError> {
        let mut generator = Generator::default();
        let container_name = generator.next().unwrap();

        let mut container = core::LxcContainer::launch(&self.image_name, container_name.into())?;

        func(&mut container)?;
        
        container.stop()?;
        container.delete()
    }
}

