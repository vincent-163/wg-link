use crate::shortcut::{
    base_control::CONTROL_SOCKET_MARK,
    state::{RouteManager, RouteTarget},
};
use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use std::{
    collections::HashMap,
    net::IpAddr,
    ops::Range,
    process::{Command, Output},
};

pub const DEFAULT_TABLE: u32 = 51_820;
pub const DEFAULT_RULE_PRIORITY_BASE: u32 = 11_000;
const CONTROL_RULE_PRIORITY: u32 = 10_500;
const MANAGED_RULE_PRIORITY_RANGE: Range<u32> = 11_000..21_000;

pub trait UserspaceRoutes {
    fn replace(&mut self, selector: IpNet, target: RouteTarget) -> Result<()>;
    fn remove(&mut self, selector: IpNet) -> Result<()>;
}

pub trait PolicyRules {
    fn install(&mut self, selector: IpNet) -> Result<()>;
    fn remove(&mut self, selector: IpNet) -> Result<()>;
}

pub struct AtomicRouteManager<U, P> {
    userspace: U,
    policy: P,
    active: HashMap<IpNet, RouteTarget>,
}

impl<U, P> AtomicRouteManager<U, P> {
    pub fn new(userspace: U, policy: P) -> Self {
        Self {
            userspace,
            policy,
            active: HashMap::new(),
        }
    }
}

impl<U: UserspaceRoutes, P: PolicyRules> RouteManager for AtomicRouteManager<U, P> {
    fn activate(&mut self, selector: IpNet, target: RouteTarget) -> Result<()> {
        let previous = self.active.get(&selector).copied();
        self.userspace.replace(selector, target)?;
        if let Err(error) = self.policy.install(selector) {
            match previous {
                Some(previous) => self.userspace.replace(selector, previous)?,
                None => self.userspace.remove(selector)?,
            }
            return Err(error);
        }
        self.active.insert(selector, target);
        Ok(())
    }

    fn deactivate(&mut self, selector: IpNet) -> Result<()> {
        self.policy.remove(selector)?;
        self.userspace.remove(selector)?;
        self.active.remove(&selector);
        Ok(())
    }
}

pub struct SystemPolicy {
    tun_name: String,
    table: u32,
    priority_base: u32,
    source: Option<IpAddr>,
}

impl SystemPolicy {
    pub fn new(tun_name: impl Into<String>) -> Self {
        Self {
            tun_name: tun_name.into(),
            table: DEFAULT_TABLE,
            priority_base: DEFAULT_RULE_PRIORITY_BASE,
            source: None,
        }
    }

    pub fn new_with_source(tun_name: impl Into<String>, source: IpAddr) -> Self {
        Self {
            tun_name: tun_name.into(),
            table: DEFAULT_TABLE,
            priority_base: DEFAULT_RULE_PRIORITY_BASE,
            source: Some(source),
        }
    }

    pub fn cleanup_stale(&self) -> Result<()> {
        self.remove_control_bypass()?;
        for family in ["-4", "-6"] {
            let output = ip_output([family, "rule", "show"])?;
            if !output.status.success() {
                bail!(
                    "ip {family} rule show failed: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
            for priority in String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter_map(|line| {
                    parse_managed_rule(line, self.table, &MANAGED_RULE_PRIORITY_RANGE)
                })
            {
                let priority = priority.to_string();
                let table = self.table.to_string();
                run_ip([
                    family,
                    "rule",
                    "del",
                    "priority",
                    priority.as_str(),
                    "lookup",
                    table.as_str(),
                ])?;
            }
            let table = self.table.to_string();
            let output = ip_output([family, "route", "flush", "table", table.as_str()])?;
            if !output.status.success()
                && !String::from_utf8_lossy(&output.stderr).contains("FIB table does not exist")
            {
                bail!(
                    "ip {family} route flush failed: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
        }
        Ok(())
    }

    pub fn ensure_control_bypass(&self) -> Result<()> {
        for family in ["-4", "-6"] {
            let priority = CONTROL_RULE_PRIORITY.to_string();
            let mark = format!("0x{CONTROL_SOCKET_MARK:x}/0xffff");
            let output = ip_output([
                family,
                "rule",
                "add",
                "priority",
                priority.as_str(),
                "fwmark",
                mark.as_str(),
                "lookup",
                "main",
            ])?;
            if !output.status.success()
                && !String::from_utf8_lossy(&output.stderr).contains("File exists")
            {
                bail!(
                    "ip {family} control bypass rule add failed: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
        }
        Ok(())
    }

    fn remove_control_bypass(&self) -> Result<()> {
        for family in ["-4", "-6"] {
            let priority = CONTROL_RULE_PRIORITY.to_string();
            let mark = format!("0x{CONTROL_SOCKET_MARK:x}/0xffff");
            let output = ip_output([
                family,
                "rule",
                "del",
                "priority",
                priority.as_str(),
                "fwmark",
                mark.as_str(),
                "lookup",
                "main",
            ])?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.contains("No such file") && !stderr.contains("No such process") {
                    bail!(
                        "ip {family} control bypass rule removal failed: {}",
                        stderr.trim()
                    );
                }
            }
        }
        Ok(())
    }

    fn prepare(&self, selector: IpNet) -> Result<()> {
        let table = self.table.to_string();
        let source = self.source.map(|source| source.to_string());
        let mut arguments = Vec::new();
        if selector.addr().is_ipv6() {
            arguments.push("-6");
        }
        arguments.extend([
            "route",
            "replace",
            "default",
            "dev",
            self.tun_name.as_str(),
            "table",
            table.as_str(),
        ]);
        if let Some(source) = source.as_deref() {
            arguments.extend(["src", source]);
        }
        run_ip(arguments)?;
        Ok(())
    }

    fn priority(&self, selector: IpNet) -> u32 {
        let digest = blake3::hash(selector.to_string().as_bytes());
        let offset = u16::from_le_bytes([digest.as_bytes()[0], digest.as_bytes()[1]]) as u32;
        self.priority_base + offset % 10_000
    }

    fn rule_arguments<'a>(
        &self,
        operation: &'a str,
        selector: IpNet,
        priority: &'a str,
        table: &'a str,
        selector_text: &'a str,
    ) -> Vec<&'a str> {
        let mut arguments = Vec::new();
        if selector.addr().is_ipv6() {
            arguments.push("-6");
        }
        arguments.extend([
            "rule",
            operation,
            "priority",
            priority,
            "to",
            selector_text,
            "lookup",
            table,
        ]);
        arguments
    }
}

impl PolicyRules for SystemPolicy {
    fn install(&mut self, selector: IpNet) -> Result<()> {
        self.prepare(selector)?;
        let priority = self.priority(selector).to_string();
        let table = self.table.to_string();
        let selector_text = selector.to_string();
        let output =
            ip_output(self.rule_arguments("add", selector, &priority, &table, &selector_text))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("File exists") {
                bail!("ip rule add failed: {}", stderr.trim());
            }
        }
        Ok(())
    }

    fn remove(&mut self, selector: IpNet) -> Result<()> {
        let priority = self.priority(selector).to_string();
        let table = self.table.to_string();
        let selector_text = selector.to_string();
        let output =
            ip_output(self.rule_arguments("del", selector, &priority, &table, &selector_text))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("No such file") && !stderr.contains("No such process") {
                bail!("ip rule del failed: {}", stderr.trim());
            }
        }
        Ok(())
    }
}

fn run_ip(arguments: impl IntoIterator<Item = impl AsRef<std::ffi::OsStr>>) -> Result<Output> {
    let output = ip_output(arguments)?;
    if !output.status.success() {
        bail!(
            "ip command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output)
}

fn ip_output(arguments: impl IntoIterator<Item = impl AsRef<std::ffi::OsStr>>) -> Result<Output> {
    Command::new("ip")
        .args(arguments)
        .output()
        .context("failed to run ip")
}

fn parse_managed_rule(line: &str, table: u32, priority_range: &Range<u32>) -> Option<u32> {
    let mut fields = line.split_whitespace();
    let priority = fields.next()?.trim_end_matches(':').parse().ok()?;
    if !priority_range.contains(&priority) {
        return None;
    }
    let lookup = fields
        .collect::<Vec<_>>()
        .windows(2)
        .find_map(|pair| (pair[0] == "lookup").then_some(pair[1]))?;
    (lookup == table.to_string()).then_some(priority)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shortcut::{control::ShortcutId, state::SessionKey};
    use std::{cell::RefCell, rc::Rc, str::FromStr};

    #[derive(Clone)]
    struct Recorder {
        events: Rc<RefCell<Vec<String>>>,
        fail_install: bool,
    }

    impl Recorder {
        fn new(events: Rc<RefCell<Vec<String>>>) -> Self {
            Self {
                events,
                fail_install: false,
            }
        }
    }

    impl UserspaceRoutes for Recorder {
        fn replace(&mut self, selector: IpNet, target: RouteTarget) -> Result<()> {
            self.events.borrow_mut().push(format!(
                "userspace:replace:{selector}:{}",
                target.session.epoch
            ));
            Ok(())
        }

        fn remove(&mut self, selector: IpNet) -> Result<()> {
            self.events
                .borrow_mut()
                .push(format!("userspace:remove:{selector}"));
            Ok(())
        }
    }

    impl PolicyRules for Recorder {
        fn install(&mut self, selector: IpNet) -> Result<()> {
            self.events
                .borrow_mut()
                .push(format!("policy:install:{selector}"));
            if self.fail_install {
                bail!("injected policy failure");
            }
            Ok(())
        }

        fn remove(&mut self, selector: IpNet) -> Result<()> {
            self.events
                .borrow_mut()
                .push(format!("policy:remove:{selector}"));
            Ok(())
        }
    }

    fn target(epoch: u64) -> RouteTarget {
        RouteTarget {
            session: SessionKey {
                shortcut_id: ShortcutId([1; 16]),
                epoch,
            },
        }
    }

    #[test]
    fn installs_userspace_target_before_kernel_policy_rule() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut routes =
            AtomicRouteManager::new(Recorder::new(events.clone()), Recorder::new(events.clone()));
        let selector = IpNet::from_str("198.51.100.7/32").unwrap();
        routes.activate(selector, target(1)).unwrap();
        assert_eq!(
            events.borrow().as_slice(),
            [
                "userspace:replace:198.51.100.7/32:1",
                "policy:install:198.51.100.7/32"
            ]
        );
    }

    #[test]
    fn policy_failure_rolls_back_userspace_target() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let userspace = Recorder::new(events.clone());
        let mut policy = Recorder::new(events.clone());
        policy.fail_install = true;
        let mut routes = AtomicRouteManager::new(userspace, policy);
        let selector = IpNet::from_str("198.51.100.7/32").unwrap();
        assert!(routes.activate(selector, target(1)).is_err());
        assert_eq!(
            events.borrow().as_slice(),
            [
                "userspace:replace:198.51.100.7/32:1",
                "policy:install:198.51.100.7/32",
                "userspace:remove:198.51.100.7/32"
            ]
        );
    }

    #[test]
    fn removes_kernel_rule_before_userspace_target() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut routes =
            AtomicRouteManager::new(Recorder::new(events.clone()), Recorder::new(events.clone()));
        let selector = IpNet::from_str("198.51.100.7/32").unwrap();
        routes.activate(selector, target(1)).unwrap();
        events.borrow_mut().clear();
        routes.deactivate(selector).unwrap();
        assert_eq!(
            events.borrow().as_slice(),
            [
                "policy:remove:198.51.100.7/32",
                "userspace:remove:198.51.100.7/32"
            ]
        );
    }

    #[test]
    fn parses_only_managed_rules_for_dedicated_table() {
        let range = 11_000..21_000;
        assert_eq!(
            parse_managed_rule(
                "11042: from all to 192.168.38.2 lookup 51820",
                51_820,
                &range
            ),
            Some(11_042)
        );
        assert_eq!(
            parse_managed_rule("100: from all lookup 51820", 51_820, &range),
            None
        );
        assert_eq!(
            parse_managed_rule("11042: from all lookup main", 51_820, &range),
            None
        );
        assert_eq!(
            parse_managed_rule("11042: from all lookup 51821", 51_820, &range),
            None
        );
    }
}
