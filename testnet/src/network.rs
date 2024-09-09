use std::ffi::c_int;
use std::ffi::CString;
use std::fmt::Debug;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::fd::RawFd;

use ipnet::IpNet;
use netlink_packet_core::NetlinkDeserializable;
use netlink_packet_core::NetlinkMessage;
use netlink_packet_core::NetlinkPayload;
use netlink_packet_core::NetlinkSerializable;
use netlink_packet_core::NLM_F_ACK;
use netlink_packet_core::NLM_F_CREATE;
use netlink_packet_core::NLM_F_EXCL;
use netlink_packet_core::NLM_F_REQUEST;
use netlink_packet_route::address::AddressAttribute;
use netlink_packet_route::address::AddressMessage;
use netlink_packet_route::link::InfoData;
use netlink_packet_route::link::InfoKind;
use netlink_packet_route::link::InfoVeth;
use netlink_packet_route::link::LinkAttribute;
use netlink_packet_route::link::LinkFlags;
use netlink_packet_route::link::LinkInfo;
use netlink_packet_route::link::LinkMessage;
use netlink_packet_route::RouteNetlinkMessage;
use nix::errno::Errno;
use nix::sched::CloneFlags;
use nix::sys::prctl::set_name;
use nix::sys::socket::socket;
use nix::sys::socket::AddressFamily;
use nix::sys::socket::SockFlag;
use nix::sys::socket::SockProtocol;
use nix::sys::socket::SockType;
use nix::sys::wait::WaitStatus;
use nix::unistd::pipe;
use nix::unistd::sethostname;
use nix::unistd::Gid;
use nix::unistd::Pid;
use nix::unistd::Uid;

use crate::CallbackResult;
use crate::Context;
use crate::IpcClient;
use crate::IpcServer;
use crate::NetConfig;
use crate::NodeConfig;
use crate::Process;

pub struct Network {
    main: Process,
}

impl Network {
    pub fn new<F: FnOnce(Context) -> CallbackResult + Clone>(
        config: NetConfig<F>,
    ) -> Result<Self, std::io::Error> {
        let (sender, receiver) = pipe_channel()?;
        let main = Process::spawn(
            || network_switch_main(receiver.into(), config),
            STACK_SIZE,
            CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWUTS,
        )?;
        // update uid map
        std::fs::write(
            format!("/proc/{}/uid_map", main.id()),
            format!("0 {} 1", Uid::current()),
        )?;
        // setgroups deny
        std::fs::write(format!("/proc/{}/setgroups", main.id()), "deny")?;
        // update gid map
        std::fs::write(
            format!("/proc/{}/gid_map", main.id()),
            format!("0 {} 1", Gid::current()),
        )?;
        // notify the child process
        sender.close();
        Ok(Self { main })
    }

    pub fn wait(&self) -> Result<WaitStatus, Errno> {
        self.main.wait()
    }
}

fn network_switch_main<F: FnOnce(Context) -> CallbackResult + Clone>(
    receiver: PipeReceiver,
    config: NetConfig<F>,
) -> c_int {
    match do_network_switch_main(receiver, config) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("network main failed: {}", e);
            1
        }
    }
}

fn do_network_switch_main<F: FnOnce(Context) -> CallbackResult + Clone>(
    receiver: PipeReceiver,
    config: NetConfig<F>,
) -> CallbackResult {
    set_process_name("switch")?;
    sethostname("switch")?;
    // wait for uid/gid mappings to be done by the parent process
    receiver.wait_until_closed()?;
    let mut netlink = Netlink::new(SockProtocol::NetlinkRoute)?;
    netlink.new_bridge("testnet")?;
    let bridge_index = netlink.index("testnet")?;
    let mut nodes: Vec<Process> = Vec::with_capacity(config.nodes.len());
    let net = IpNet::new(Ipv4Addr::new(10, 84, 0, 0).into(), 16)?;
    let mut all_node_configs = Vec::with_capacity(config.nodes.len());
    for (i, mut node_config) in config.nodes.into_iter().enumerate() {
        if node_config.name.is_empty() {
            node_config.name = outer_ifname(i);
        }
        if node_config.ifaddr.addr().is_unspecified() {
            node_config.ifaddr = IpNet::new(
                net.hosts()
                    .nth(i)
                    .ok_or("exhausted available IP adddress range")?,
                net.prefix_len(),
            )?;
        }
        all_node_configs.push(node_config);
    }
    let mut ipc_fds: Vec<(OwnedFd, OwnedFd)> = Vec::with_capacity(all_node_configs.len());
    for i in 0..all_node_configs.len() {
        let outer = outer_ifname(i);
        netlink.new_veth_pair(outer.clone(), INNER_IFNAME)?;
        netlink.set_up(outer.clone())?;
        netlink.set_bridge(outer, bridge_index)?;
        let (sender, receiver) = pipe_channel()?;
        let (in_self, out_other) = pipe()?;
        let (in_other, out_self) = pipe()?;
        let in_self_fd = in_self.as_raw_fd();
        let in_other_fd = in_other.as_raw_fd();
        let out_self_fd = out_self.as_raw_fd();
        let out_other_fd = out_other.as_raw_fd();
        let callback = config.callback.clone();
        let all_node_configs = all_node_configs.clone();
        let process = Process::spawn(
            || {
                // drop unused pipe ends
                unsafe {
                    OwnedFd::from_raw_fd(in_self_fd);
                    OwnedFd::from_raw_fd(out_self_fd);
                }
                network_node_main(
                    receiver.into(),
                    in_other_fd,
                    out_other_fd,
                    i,
                    callback,
                    all_node_configs,
                )
            },
            STACK_SIZE,
            CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWUTS,
        )?;
        netlink.set_network_namespace(INNER_IFNAME, process.id())?;
        // notify the child process
        sender.close();
        // drop unused pipe ends
        drop(in_other);
        drop(out_other);
        nodes.push(process);
        ipc_fds.push((in_self, out_self));
    }
    let mut ipc_server = IpcServer::new(ipc_fds)?;
    ipc_server.run()?;
    let mut all_ret = Vec::with_capacity(nodes.len());
    for node in nodes.into_iter() {
        let status = node.wait()?;
        all_ret.push(status);
    }
    if all_ret.iter().all(wait_status_ok) {
        Ok(())
    } else {
        use std::fmt::Write;
        let mut buf = String::with_capacity(4096);
        writeln!(&mut buf, "some nodes failed:")?;
        for (i, status) in all_ret.into_iter().enumerate() {
            writeln!(
                &mut buf,
                "- node {} exited with {}",
                i,
                wait_status_to_string(status)
            )?;
        }
        Err(buf.into())
    }
}

fn network_node_main<F: FnOnce(Context) -> CallbackResult>(
    receiver: PipeReceiver,
    ipc_in_fd: RawFd,
    ipc_out_fd: RawFd,
    i: usize,
    callback: F,
    node_config: Vec<NodeConfig>,
) -> c_int {
    match do_network_node_main(receiver, ipc_in_fd, ipc_out_fd, i, callback, node_config) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("child main failed: {}", e);
            1
        }
    }
}

fn do_network_node_main<F: FnOnce(Context) -> CallbackResult>(
    receiver: PipeReceiver,
    ipc_in_fd: RawFd,
    ipc_out_fd: RawFd,
    i: usize,
    callback: F,
    nodes: Vec<NodeConfig>,
) -> CallbackResult {
    set_process_name(&nodes[i].name)?;
    sethostname(&nodes[i].name)?;
    // wait for veth to be trasnferred to this process' network namespace
    receiver.wait_until_closed()?;
    let mut netlink = Netlink::new(SockProtocol::NetlinkRoute)?;
    netlink.set_up("lo")?;
    let inner_index = netlink.index(INNER_IFNAME)?;
    netlink.set_up(INNER_IFNAME)?;
    netlink.set_ifaddr(inner_index, nodes[i].ifaddr)?;
    let ipc_in_fd = unsafe { OwnedFd::from_raw_fd(ipc_in_fd) };
    let ipc_out_fd = unsafe { OwnedFd::from_raw_fd(ipc_out_fd) };
    let context = Context {
        node_index: i,
        nodes,
        ipc_client: IpcClient::new(ipc_in_fd, ipc_out_fd),
    };
    callback(context).map_err(|e| format!("error in node main: {}", e).into())
}

struct Netlink {
    socket: OwnedFd,
}

impl Netlink {
    pub fn new(protocol: SockProtocol) -> Result<Self, std::io::Error> {
        let socket = socket(
            AddressFamily::Netlink,
            SockType::Raw,
            SockFlag::SOCK_CLOEXEC,
            protocol,
        )?;
        Ok(Self { socket })
    }

    pub fn new_veth_pair(
        &mut self,
        name: impl ToString,
        peer_name: impl ToString,
    ) -> Result<(), std::io::Error> {
        let mut peer = LinkMessage::default();
        peer.attributes
            .push(LinkAttribute::IfName(name.to_string()));
        let link_info_data = InfoData::Veth(InfoVeth::Peer(peer));
        let mut link = LinkMessage::default();
        link.attributes
            .push(LinkAttribute::IfName(peer_name.to_string()));
        link.attributes.push(LinkAttribute::LinkInfo(vec![
            LinkInfo::Kind(InfoKind::Veth),
            LinkInfo::Data(link_info_data),
        ]));
        link.header.flags.insert(LinkFlags::Up);
        link.header.change_mask.insert(LinkFlags::Up);
        let mut message = NetlinkMessage::from(RouteNetlinkMessage::NewLink(link));
        message.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;
        message.finalize();
        let message = self.send(&message)?;
        check_ok(message)?;
        Ok(())
    }

    pub fn new_bridge(&mut self, name: impl ToString) -> Result<(), std::io::Error> {
        let mut link = LinkMessage::default();
        link.attributes
            .push(LinkAttribute::IfName(name.to_string()));
        link.attributes
            .push(LinkAttribute::LinkInfo(vec![LinkInfo::Kind(
                InfoKind::Bridge,
            )]));
        link.header.flags.insert(LinkFlags::Up);
        link.header.change_mask.insert(LinkFlags::Up);
        let mut message = NetlinkMessage::from(RouteNetlinkMessage::NewLink(link));
        message.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;
        message.finalize();
        let message = self.send(&message)?;
        check_ok(message)?;
        Ok(())
    }

    pub fn set_up(&mut self, name: impl ToString) -> Result<(), std::io::Error> {
        let mut link = LinkMessage::default();
        link.attributes
            .push(LinkAttribute::IfName(name.to_string()));
        link.header.flags.insert(LinkFlags::Up);
        link.header.change_mask.insert(LinkFlags::Up);
        let mut message = NetlinkMessage::from(RouteNetlinkMessage::SetLink(link));
        message.header.flags = NLM_F_REQUEST | NLM_F_ACK;
        message.finalize();
        let message = self.send(&message)?;
        check_ok(message)?;
        Ok(())
    }

    pub fn set_bridge(&mut self, name: String, bridge_index: u32) -> Result<(), std::io::Error> {
        let mut link = LinkMessage::default();
        link.attributes.push(LinkAttribute::IfName(name));
        link.attributes
            .push(LinkAttribute::Controller(bridge_index));
        let mut message = NetlinkMessage::from(RouteNetlinkMessage::SetLink(link));
        message.header.flags = NLM_F_REQUEST | NLM_F_ACK;
        message.finalize();
        let message = self.send(&message)?;
        check_ok(message)?;
        Ok(())
    }

    pub fn set_network_namespace(
        &mut self,
        name: impl ToString,
        pid: Pid,
    ) -> Result<(), std::io::Error> {
        let mut link = LinkMessage::default();
        link.attributes
            .push(LinkAttribute::IfName(name.to_string()));
        link.attributes
            .push(LinkAttribute::NetNsPid(pid.as_raw() as u32));
        let mut message = NetlinkMessage::from(RouteNetlinkMessage::SetLink(link));
        message.header.flags = NLM_F_REQUEST | NLM_F_ACK;
        message.finalize();
        let message = self.send(&message)?;
        check_ok(message)?;
        Ok(())
    }

    pub fn set_ifaddr(&mut self, index: u32, ifaddr: IpNet) -> Result<(), std::io::Error> {
        use netlink_packet_route::AddressFamily;
        let mut message = AddressMessage::default();
        message.header.prefix_len = ifaddr.prefix_len();
        message.header.index = index;
        message.header.family = match ifaddr {
            IpNet::V4(_) => AddressFamily::Inet,
            IpNet::V6(_) => AddressFamily::Inet6,
        };
        message
            .attributes
            .push(AddressAttribute::Address(ifaddr.addr()));
        message
            .attributes
            .push(AddressAttribute::Local(ifaddr.addr()));
        let mut message = NetlinkMessage::from(RouteNetlinkMessage::NewAddress(message));
        message.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;
        message.finalize();
        let message = self.send(&message)?;
        check_ok(message)?;
        Ok(())
    }

    pub fn index(&mut self, name: impl ToString) -> Result<u32, std::io::Error> {
        let mut link = LinkMessage::default();
        link.attributes
            .push(LinkAttribute::IfName(name.to_string()));
        let mut message = NetlinkMessage::from(RouteNetlinkMessage::GetLink(link));
        message.header.flags = NLM_F_REQUEST | NLM_F_ACK;
        message.finalize();
        let message = self.send(&message)?;
        let index = match message.payload {
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(ref inner)) => {
                Some(inner.header.index)
            }
            _ => None,
        };
        match index {
            Some(index) => Ok(index),
            None => Err(std::io::Error::other(format!(
                "netlink returned unexpected data: {:?}",
                message,
            ))),
        }
    }

    fn send<I: NetlinkSerializable + NetlinkDeserializable + Debug>(
        &mut self,
        message: &NetlinkMessage<I>,
    ) -> Result<NetlinkMessage<I>, std::io::Error> {
        let mut buf = vec![0_u8; message.header.length as usize];
        // Serialize the packet
        message.serialize(&mut buf[..]);
        let n = nix::unistd::write(&mut self.socket, &buf)?;
        if n != buf.len() {
            return Err(std::io::Error::other("partial write"));
        }
        buf.clear();
        buf.resize(4096, 0_u8);
        let n = nix::unistd::read(self.socket.as_raw_fd(), &mut buf)?;
        buf.truncate(n);
        let message = NetlinkMessage::<I>::deserialize(&buf)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(message)
    }
}

fn check_ok<I: Debug>(message: NetlinkMessage<I>) -> Result<NetlinkMessage<I>, std::io::Error> {
    match message.payload {
        NetlinkPayload::Error(ref error) => {
            if let Some(code) = error.code {
                return Err(std::io::Error::other(format!(
                    "netlink failed with error code {}",
                    code
                )));
            }
        }
        other => {
            return Err(std::io::Error::other(format!(
                "netlink returned unexpected data: {:?}",
                other,
            )));
        }
    }
    Ok(message)
}

fn pipe_channel() -> Result<(PipeSender, RawPipeReceiver), std::io::Error> {
    let (pipe_in, pipe_out) = pipe()?;
    let receiver = RawPipeReceiver::new(pipe_in.as_raw_fd(), pipe_out.as_raw_fd());
    let sender = PipeSender::new(pipe_in, pipe_out);
    Ok((sender, receiver))
}

struct RawPipeReceiver {
    fd_in: RawFd,
    fd_out: RawFd,
}

impl RawPipeReceiver {
    fn new(fd_in: RawFd, fd_out: RawFd) -> Self {
        Self { fd_in, fd_out }
    }
}

struct PipeReceiver {
    fd: OwnedFd,
}

impl PipeReceiver {
    fn new(fd_in: RawFd, fd_out: RawFd) -> Self {
        // drop sender
        unsafe { OwnedFd::from_raw_fd(fd_out) };
        Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd_in) },
        }
    }

    fn wait_until_closed(&self) -> Result<(), std::io::Error> {
        let mut buf = [0_u8; 1];
        let ret = nix::unistd::read(self.fd.as_raw_fd(), &mut buf)?;
        eprintln!("wait_until_closed ret {:?}", ret);
        Ok(())
    }
}

impl From<RawPipeReceiver> for PipeReceiver {
    fn from(other: RawPipeReceiver) -> Self {
        Self::new(other.fd_in, other.fd_out)
    }
}

struct PipeSender {
    #[allow(dead_code)]
    fd_in: OwnedFd,
    #[allow(dead_code)]
    fd_out: OwnedFd,
}

impl PipeSender {
    fn new(fd_in: OwnedFd, fd_out: OwnedFd) -> Self {
        // drop receiver
        Self { fd_in, fd_out }
    }

    fn close(self) {
        // drop self
    }
}

fn wait_status_ok(status: &WaitStatus) -> bool {
    matches!(status, WaitStatus::Exited(_, code) if code == &0)
}

fn wait_status_to_string(status: WaitStatus) -> String {
    match status {
        WaitStatus::Exited(_, code) => format!("code {}", code),
        WaitStatus::Signaled(_, signal, _) => format!("signal {:?}", signal),
        _ => "unknown".to_string(),
    }
}

fn outer_ifname(i: usize) -> String {
    format!("n{}", i)
}

fn set_process_name(name: &str) -> Result<(), std::io::Error> {
    let name = format!("testnet/{}", name);
    let c_string = CString::new(name)?;
    Ok(set_name(c_string.as_c_str())?)
}

const STACK_SIZE: usize = 4096 * 16;
const INNER_IFNAME: &str = "veth";
