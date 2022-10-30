use std::{
    collections::HashMap,
    io,
    net::IpAddr,
    path::{Path, PathBuf},
    process::{Command, Output},
    str::FromStr,
};

use serde::Deserialize;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum LxcContainerError {
    #[error(transparent)]
    Io {
        #[from]
        source: io::Error,
    },
    #[error("lxc error: {0}")]
    LxcCommand(String),
    #[error(transparent)]
    InfoParseError {
        #[from]
        source: serde_json::Error,
    },
}

#[derive(Deserialize, Debug)]
pub struct LxcContainer {
    pub name: String,
}

impl LxcContainer {
    pub fn launch(image_name: &str, instance_name: String) -> Result<Self, LxcContainerError> {
        lxc_command(|cmd| cmd.arg("launch").arg(image_name).arg(&instance_name))?;

        Ok(Self {
            name: instance_name,
        })
    }

    pub fn stop(&self) -> Result<(), LxcContainerError> {
        lxc_command(|cmd| cmd.arg("stop").arg(&self.name))?;

        Ok(())
    }

    pub fn delete(&self) -> Result<(), LxcContainerError> {
        lxc_command(|cmd| cmd.arg("delete").arg(&self.name))?;

        Ok(())
    }

    pub fn get_info(&self) -> Result<InstanceInfo, LxcContainerError> {
        let output = lxc_command(|cmd| {
            cmd.arg("list")
                .arg(format!("{}$", self.name)) // $ is used for an exact match
                .args(["--format", "json"])
        })?;

        let json = String::from_utf8_lossy(&output.stdout);
        let instance_infos: Vec<InstanceInfo> = serde_json::from_str(&json)?;

        Ok(instance_infos.into_iter().next().unwrap())
    }

    pub fn get_ips(&self) -> Result<Vec<IpAddr>, LxcContainerError> {
        let output = lxc_command(|cmd| {
            cmd.arg("list")
                // filtering does not work when --format is json
                //.arg(format!("{}$", self.name)) // $ is used for an exact match
                .args(["--format", "json"])
        })?;

        let json = String::from_utf8(output.stdout).unwrap();
        let instances: Vec<InstanceInfo> = serde_json::from_str(&json).unwrap();
        // filtering does not work when --format is json
        // so we have to filter it in code
        let instances: Vec<InstanceInfo> = instances
            .into_iter()
            .filter(|i| i.name.eq(&self.name))
            .collect();

        Ok(instances
            .first()
            .unwrap()
            .state
            .network
            .as_ref()
            .unwrap()
            .get("eth0")
            .unwrap()
            .addresses
            .clone())
    }

    pub fn exec(
        &self,
        f: &dyn Fn(&mut Command) -> &mut Command,
    ) -> Result<Output, LxcContainerError> {
        lxc_command(|cmd| {
            let c = cmd.arg("exec").arg(self.name.clone()).arg("--");

            f(c)
        })
    }

    pub fn file_push(
        &self,
        source_path: &impl AsRef<Path>,
        destination_path: &impl AsRef<Path>,
    ) -> Result<(), LxcContainerError> {
        let mut container_dest_path = PathBuf::from(self.name.clone());
        container_dest_path.push(destination_path);

        lxc_command(|cmd| {
            cmd.arg("file")
                .arg("push")
                .arg(source_path.as_ref())
                .arg(container_dest_path.as_os_str())
        })?;

        Ok(())
    }
}

#[derive(PartialEq, Deserialize, Debug)]
pub struct InstanceInfo {
    name: String,
    state: InstanceState,
}

#[derive(PartialEq, Deserialize, Debug)]
pub struct InstanceState {
    network: Option<HashMap<String, NetworkAdapter>>,
}

#[derive(PartialEq, Deserialize, Debug)]
pub struct NetworkAdapter {
    #[serde(deserialize_with = "addresses_object_to_vec")]
    addresses: Vec<IpAddr>,
}

fn addresses_object_to_vec<'de, D>(deserializer: D) -> Result<Vec<IpAddr>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    struct AddressObject {
        address: String,
    }

    let addresses = Vec::<AddressObject>::deserialize(deserializer)?
        .into_iter()
        .map(|AddressObject { address }| IpAddr::from_str(&address).unwrap())
        .collect();

    Ok(addresses)
}

fn lxc_command<F: FnOnce(&mut Command) -> &mut Command>(
    func: F,
) -> Result<Output, LxcContainerError> {
    let mut command = Command::new("lxc");

    let output = func(&mut command).output()?;

    if output.status.success() {
        Ok(output)
    } else {
        let mut error = String::from_utf8_lossy(&output.stdout).into_owned();
        error.push_str(&String::from_utf8_lossy(&output.stderr).into_owned());
        Err(LxcContainerError::LxcCommand(error))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn parse_lxc_info_json() {
        let json = r#"
{
    "state" : {
        "network" : {
            "eth0" : {
                "addresses" : [
                    {
                       "address" : "10.228.250.181",
                       "family" : "inet",
                       "netmask" : "24",
                       "scope" : "global"
                    },
                    {
                       "address" : "fd42:528d:b20d:4e5f:216:3eff:fe44:add9",
                       "family" : "inet6",
                       "netmask" : "64",
                       "scope" : "global"
                    },
                    {
                       "address" : "fe80::216:3eff:fe44:add9",
                       "family" : "inet6",
                       "netmask" : "64",
                       "scope" : "link"
                    }
                ]
            }
        }
    }
}
"#;
        assert_eq!(
            serde_json::from_str::<InstanceInfo>(&json).unwrap(),
            InstanceInfo {
                state: InstanceState {
                    network: HashMap::from([(
                        "eth0".to_string(),
                        NetworkAdapter {
                            addresses: vec![
                                "10.228.250.181".parse().unwrap(),
                                "fd42:528d:b20d:4e5f:216:3eff:fe44:add9".parse().unwrap(),
                                "fe80::216:3eff:fe44:add9".parse().unwrap()
                            ]
                        }
                    )])
                }
            }
        );
    }
}
