use eframe::egui;
use std::sync::mpsc;
use std::thread;

#[cfg(unix)]
use pnet::datalink;
#[cfg(unix)]
use pnet::packet::icmpv6::{Icmpv6Types, Icmpv6Code, MutableIcmpv6Packet};
#[cfg(unix)]
use pnet::packet::ipv6::MutableIpv6Packet;
#[cfg(unix)]
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
#[cfg(unix)]
use pnet::packet::Packet;
#[cfg(unix)]
use pnet::util::MacAddr;
#[cfg(unix)]
use std::net::Ipv6Addr;

#[cfg(windows)]
use windows::Win32::NetworkManagement::IpHelper::*;
#[cfg(windows)]
use winapi::um::winsock2::{
    WSAStartup, WSACleanup, WSAGetLastError, WSADATA, INVALID_SOCKET, SOCKET_ERROR,
    socket, sendto, closesocket
};
#[cfg(windows)]
use winapi::shared::ws2def::{SOCK_RAW, AF_INET6, SOCKADDR};
#[cfg(windows)]
use winapi::shared::ws2ipdef::SOCKADDR_IN6;
#[cfg(windows)]
use std::mem;

// Define ICMPv6 protocol number since it's not in winapi
#[cfg(windows)]
const IPPROTO_ICMPV6: i32 = 58;

// Cross-platform network interface representation
#[derive(Clone)]
struct AppNetworkInterface {
    name: String,
    index: u32,
    mac: Option<String>,
    ips: Vec<String>,
    is_up: bool,
    is_loopback: bool,
}

#[derive(Default)]
struct RouterSolicitationApp {
    interfaces: Vec<AppNetworkInterface>,
    selected_interface: Option<usize>,
    status_message: String,
    message_receiver: Option<mpsc::Receiver<String>>,
}

impl RouterSolicitationApp {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let interfaces = get_network_interfaces()
            .into_iter()
            .filter(|iface| !iface.is_loopback && iface.is_up)
            .collect();

        Self {
            interfaces,
            selected_interface: None,
            status_message: "Ready".to_string(),
            message_receiver: None,
        }
    }

    fn send_router_solicitation(&mut self) {
        if let Some(index) = self.selected_interface {
            if let Some(interface) = self.interfaces.get(index) {
                let (tx, rx) = mpsc::channel();
                self.message_receiver = Some(rx);
                
                let interface_clone = interface.clone();
                thread::spawn(move || {
                    match send_rs_packet(&interface_clone) {
                        Ok(_) => {
                            let _ = tx.send("Router Solicitation sent successfully!".to_string());
                        }
                        Err(e) => {
                            let _ = tx.send(format!("Error sending Router Solicitation: {}", e));
                        }
                    }
                });
            }
        } else {
            self.status_message = "Please select a network interface first".to_string();
        }
    }

    fn check_for_messages(&mut self) {
        if let Some(receiver) = &self.message_receiver {
            if let Ok(message) = receiver.try_recv() {
                self.status_message = message;
                self.message_receiver = None;
            }
        }
    }
}

impl eframe::App for RouterSolicitationApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.check_for_messages();
        
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("IPv6 Router Solicitation Tool");
            ui.separator();

            ui.horizontal(|ui| {
                ui.label("Network Interface:");
                
                let selected_text = if let Some(index) = self.selected_interface {
                    if let Some(interface) = self.interfaces.get(index) {
                        format!("{} ({})", interface.name, 
                               interface.mac.as_deref().unwrap_or("No MAC"))
                    } else {
                        "Select interface...".to_string()
                    }
                } else {
                    "Select interface...".to_string()
                };

                egui::ComboBox::from_label("")
                    .selected_text(selected_text)
                    .show_ui(ui, |ui| {
                        for (index, interface) in self.interfaces.iter().enumerate() {
                            let interface_text = format!("{} ({})", 
                                interface.name, 
                                interface.mac.as_deref().unwrap_or("No MAC")
                            );
                            
                            if ui.selectable_value(&mut self.selected_interface, Some(index), interface_text).clicked() {
                                self.status_message = format!("Selected interface: {}", interface.name);
                            }
                        }
                    });
            });

            ui.separator();

            if ui.button("Send Router Solicitation").clicked() {
                self.send_router_solicitation();
            }

            ui.separator();

            ui.label("Status:");
            ui.colored_label(
                if self.status_message.contains("Error") {
                    egui::Color32::RED
                } else if self.status_message.contains("successfully") {
                    egui::Color32::GREEN
                } else {
                    egui::Color32::GRAY
                },
                &self.status_message
            );

            // Show interface details if one is selected
            if let Some(index) = self.selected_interface {
                if let Some(interface) = self.interfaces.get(index) {
                    ui.separator();
                    ui.label("Interface Details:");
                    ui.monospace(format!("Name: {}", interface.name));
                    ui.monospace(format!("Index: {}", interface.index));
                    ui.monospace(format!("MAC: {}", interface.mac.as_deref().unwrap_or("None")));
                    ui.monospace(format!("IPs: {}", interface.ips.join(", ")));
                }
            }
        });

        // Request repaint to check for messages
        ctx.request_repaint();
    }
}

#[cfg(unix)]
fn get_network_interfaces() -> Vec<AppNetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .map(|iface| AppNetworkInterface {
            name: iface.name.clone(),
            index: iface.index,
            mac: iface.mac.map(|mac| mac.to_string()),
            ips: iface.ips.iter().map(|ip| ip.ip().to_string()).collect(),
            is_up: iface.is_up(),
            is_loopback: iface.is_loopback(),
        })
        .collect()
}

#[cfg(windows)]
fn get_network_interfaces() -> Vec<AppNetworkInterface> {
    let mut interfaces = Vec::new();
    
    unsafe {
        let mut adapter_info: *mut IP_ADAPTER_INFO = std::ptr::null_mut();
        let mut size = 0u32;
        
        // Get the size needed
        let _ = GetAdaptersInfo(None, &mut size);
        
        if size > 0 {
            let buffer = vec![0u8; size as usize];
            adapter_info = buffer.as_ptr() as *mut IP_ADAPTER_INFO;
            
            if GetAdaptersInfo(Some(adapter_info), &mut size) == 0 {
                let mut current = adapter_info;
                
                while !current.is_null() {
                    let adapter = &*current;
                    
                    let name = std::ffi::CStr::from_ptr(adapter.AdapterName.as_ptr() as *const i8)
                        .to_string_lossy()
                        .to_string();
                    
                    let description = std::ffi::CStr::from_ptr(adapter.Description.as_ptr() as *const i8)
                        .to_string_lossy()
                        .to_string();
                    
                    let mac = if adapter.AddressLength == 6 {
                        Some(format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                            adapter.Address[0], adapter.Address[1], adapter.Address[2],
                            adapter.Address[3], adapter.Address[4], adapter.Address[5]))
                    } else {
                        None
                    };
                    
                    let mut ips = Vec::new();
                    let mut ip_list = &adapter.IpAddressList;
                    loop {
                        let ip_str = std::ffi::CStr::from_ptr(ip_list.IpAddress.String.as_ptr() as *const i8)
                            .to_string_lossy()
                            .to_string();
                        if !ip_str.is_empty() && ip_str != "0.0.0.0" {
                            ips.push(ip_str);
                        }
                        
                        if ip_list.Next.is_null() {
                            break;
                        }
                        ip_list = &*ip_list.Next;
                    }
                    
                    interfaces.push(AppNetworkInterface {
                        name: description,
                        index: adapter.Index,
                        mac,
                        ips,
                        is_up: true, // Assume up if we can enumerate it
                        is_loopback: name.contains("Loopback") || name.contains("loopback"),
                    });
                    
                    current = adapter.Next;
                }
            }
        }
    }
    
    interfaces
}

#[cfg(unix)]
fn send_rs_packet(interface: &AppNetworkInterface) -> Result<(), Box<dyn std::error::Error>> {
    // Find the pnet interface by name
    let pnet_interface = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == interface.name)
        .ok_or("Interface not found")?;

    // Create a channel to send packets
    let (mut tx, _rx) = match datalink::channel(&pnet_interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err("Unsupported channel type".into()),
        Err(e) => return Err(format!("Failed to create channel: {}", e).into()),
    };

    // Get the interface MAC address
    let source_mac = pnet_interface.mac.ok_or("Interface has no MAC address")?;
    
    // Use IPv6 multicast MAC for all routers (33:33:00:00:00:02)
    let dest_mac = MacAddr::new(0x33, 0x33, 0x00, 0x00, 0x00, 0x02);

    // Create Router Solicitation packet
    let mut ethernet_buffer = [0u8; 86]; // Ethernet header + IPv6 header + ICMPv6 RS
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer)
        .ok_or("Failed to create Ethernet packet")?;

    // Set Ethernet header
    ethernet_packet.set_destination(dest_mac);
    ethernet_packet.set_source(source_mac);
    ethernet_packet.set_ethertype(EtherTypes::Ipv6);

    // Create IPv6 packet
    let mut ipv6_buffer = [0u8; 48]; // IPv6 header + ICMPv6 RS
    let mut ipv6_packet = MutableIpv6Packet::new(&mut ipv6_buffer)
        .ok_or("Failed to create IPv6 packet")?;

    // Set IPv6 header
    ipv6_packet.set_version(6);
    ipv6_packet.set_traffic_class(0);
    ipv6_packet.set_flow_label(0);
    ipv6_packet.set_payload_length(8); // ICMPv6 header size
    ipv6_packet.set_next_header(pnet::packet::ip::IpNextHeaderProtocols::Icmpv6);
    ipv6_packet.set_hop_limit(255);
    
    // Source: link-local address or unspecified
    let source_ip = Ipv6Addr::UNSPECIFIED;
    ipv6_packet.set_source(source_ip);
    
    // Destination: all routers multicast (ff02::2)
    let dest_ip = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
    ipv6_packet.set_destination(dest_ip);

    // Create ICMPv6 Router Solicitation
    let mut icmpv6_buffer = [0u8; 8];
    let mut icmpv6_packet = MutableIcmpv6Packet::new(&mut icmpv6_buffer)
        .ok_or("Failed to create ICMPv6 packet")?;

    icmpv6_packet.set_icmpv6_type(Icmpv6Types::RouterSolicit);
    icmpv6_packet.set_icmpv6_code(Icmpv6Code(0));
    
    // Calculate checksum
    let checksum = pnet::packet::icmpv6::checksum(&icmpv6_packet.to_immutable(), &source_ip, &dest_ip);
    icmpv6_packet.set_checksum(checksum);

    // Copy ICMPv6 packet into IPv6 payload
    ipv6_packet.set_payload(icmpv6_packet.packet());

    // Copy IPv6 packet into Ethernet payload
    ethernet_packet.set_payload(ipv6_packet.packet());

    // Send the packet
    tx.send_to(ethernet_packet.packet(), Some(pnet_interface))
        .ok_or("Failed to send packet")?
        .map_err(|e| format!("Send error: {}", e))?;

    Ok(())
}

#[cfg(windows)]
fn send_rs_packet(interface: &AppNetworkInterface) -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        // Initialize Winsock
        let mut wsa_data: WSADATA = mem::zeroed();
        let result = WSAStartup(0x0202, &mut wsa_data);
        if result != 0 {
            return Err(format!("WSAStartup failed: {}", result).into());
        }

        // Create raw ICMPv6 socket
        let socket = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
        if socket == INVALID_SOCKET {
            WSACleanup();
            return Err("Failed to create raw socket".into());
        }

        // Create Router Solicitation packet (ICMPv6)
        #[repr(C, packed)]
        struct Icmpv6RouterSolicitation {
            icmp_type: u8,     // 133
            icmp_code: u8,     // 0
            icmp_checksum: u16, // Will be calculated by kernel
            reserved: u32,     // Must be 0
        }

        let rs_packet = Icmpv6RouterSolicitation {
            icmp_type: 133,    // Router Solicitation
            icmp_code: 0,
            icmp_checksum: 0,  // Kernel will calculate
            reserved: 0,
        };

        // Destination address: ff02::2 (All Routers multicast)
        let mut dest_addr: SOCKADDR_IN6 = mem::zeroed();
        dest_addr.sin6_family = AF_INET6 as u16;
        dest_addr.sin6_port = 0;
        dest_addr.sin6_flowinfo = 0;
        
        // Set IPv6 address to ff02::2 by directly writing to the address bytes
        // Use transmute to access the raw bytes of the address
        let addr_ptr = &mut dest_addr.sin6_addr as *mut _ as *mut [u8; 16];
        (*addr_ptr)[0] = 0xff;
        (*addr_ptr)[1] = 0x02;
        (*addr_ptr)[15] = 0x02;
        
        // Set scope ID for interface binding - accessing through the union
        let scope_ptr = &mut dest_addr.u as *mut _ as *mut u32;
        *scope_ptr = interface.index;

        // Send the packet
        let packet_bytes = std::slice::from_raw_parts(
            &rs_packet as *const _ as *const u8,
            mem::size_of::<Icmpv6RouterSolicitation>()
        );

        let result = sendto(
            socket,
            packet_bytes.as_ptr() as *const i8,
            packet_bytes.len() as i32,
            0,
            &dest_addr as *const _ as *const SOCKADDR,
            mem::size_of::<SOCKADDR_IN6>() as i32,
        );

        closesocket(socket);
        WSACleanup();

        if result == SOCKET_ERROR {
            let error = WSAGetLastError();
            return Err(format!("Failed to send packet, error: {}", error).into());
        }
    }
    
    Ok(())
}

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([480.0, 400.0])
            .with_title("IPv6 Router Solicitation Tool"),
        ..Default::default()
    };

    eframe::run_native(
        "IPv6 Router Solicitation Tool",
        options,
        Box::new(|cc| Box::new(RouterSolicitationApp::new(cc))),
    )
}
