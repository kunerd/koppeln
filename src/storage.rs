use std::{
    collections::HashMap,
    net::{self},
};

use serde::{Deserialize, Serialize};

use crate::dns::DomainName;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Storage {
    mname: DomainName,
    sub_domains: HashMap<DomainName, SubDomainEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SubDomainEntry {
    #[serde(skip)]
    pub ipv4: Option<net::Ipv4Addr>,
    #[serde(skip)]
    pub ipv6: Option<net::Ipv6Addr>,
    pub token: String,
}

impl Storage {
    pub fn new(mname: DomainName, sub_domains: HashMap<DomainName, SubDomainEntry>) -> Self {
        Self { mname, sub_domains }
    }

    pub fn get(&self, name: &DomainName) -> Option<&SubDomainEntry> {
        let sub_domain = name.strip_suffix(&self.mname)?;

        self.sub_domains.get(&sub_domain)
    }

    pub fn get_mut(&mut self, name: &DomainName) -> Option<&mut SubDomainEntry> {
        let sub_domain = name.strip_suffix(&self.mname)?;

        self.sub_domains.get_mut(&sub_domain)
    }
}
