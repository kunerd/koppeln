use std::{process::{Command, Output}, path::{Path, PathBuf}};

pub struct LxcContainer {
    name: String,
}

impl LxcContainer {
    pub fn new(name: String) -> Self {
        LxcContainer { name }
    }

    pub fn exec(&self, f: &dyn Fn(&mut Command) -> &mut Command) -> std::io::Result<Output> {
        let mut cmd = Command::new("lxc");
        let c = cmd.arg("exec").arg(self.name.clone()).arg("--");

        f(c).output()
    }

    pub fn file_push(&self, source_path: &impl AsRef<Path>, destination_path: &impl AsRef<Path>) -> std::io::Result<Output> {
        //"lxc file push -p ./debian/config.toml koppeln/etc/koppeln/config.toml",
        //
        let mut container_dest_path = PathBuf::from(self.name.clone());
        container_dest_path.push(destination_path);

        println!("{:?}", container_dest_path);

        Command::new("lxc")
            .arg("file")
            .arg("push")
            .arg(source_path.as_ref())
            .arg(container_dest_path.as_os_str())
            .output()
    }
}
