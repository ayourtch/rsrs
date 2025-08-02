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
use pnet::packet::{Packet, MutablePacket};
#[cfg(unix)]
use pnet::util::MacAddr;
#[cfg(unix)]
use std::net::Ipv6Addr;

#[cfg(windows)]
use windows::Win32::NetworkManagement::IpHelper::*;
#[cfg(windows)]
use winapi::um::winsock2::{
    WSAStartup, WSACleanup, WSAGetLastError, WSADATA, INVALID_SOCKET, SOCKET_ERROR,
    socket, sendto, closesocket, setsockopt, bind
};
#[cfg(windows)]
use winapi::shared::ws2def::{SOCK_RAW, AF_INET6, SOCKADDR};
#[cfg(windows)]
use winapi::shared::ws2ipdef::SOCKADDR_IN6;
#[cfg(windows)]
use std::mem;

// Define protocol numbers and socket options
#[cfg(windows)]
const IPPROTO_ICMPV6: i32 = 58;
#[cfg(windows)]
const IPPROTO_IPV6: i32 = 41;
#[cfg(windows)]
const IPV6_UNICAST_HOPS: i32 = 4;

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
    include_source_link_addr: bool,
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
            include_source_link_addr: false,
        }
    }

    fn send_router_solicitation(&mut self) {
        if let Some(index) = self.selected_interface {
            if let Some(interface) = self.interfaces.get(index) {
                let (tx, rx) = mpsc::channel();
                self.message_receiver = Some(rx);
                
                let interface_clone = interface.clone();
                let include_slla = self.include_source_link_addr;
                thread::spawn(move || {
                    match send_rs_packet(&interface_clone, include_slla) {
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

            ui.checkbox(&mut self.include_source_link_addr, "Include Source Link-layer Address option");

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
fn send_rs_packet(interface: &AppNetworkInterface, include_slla: bool) -> Result<(), Box<dyn std::error::Error>> {
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

    // Calculate packet sizes
    let icmpv6_base_size = 8; // Basic RS header
    let slla_option_size = if include_slla { 8 } else { 0 }; // Source Link-layer Address option
    let total_icmpv6_size = icmpv6_base_size + slla_option_size;
    let total_packet_size = 14 + 40 + total_icmpv6_size; // Ethernet + IPv6 + ICMPv6

    // Create Router Solicitation packet
    let mut ethernet_buffer = vec![0u8; total_packet_size];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer)
        .ok_or("Failed to create Ethernet packet")?;

    // Set Ethernet header
    ethernet_packet.set_destination(dest_mac);
    ethernet_packet.set_source(source_mac);
    ethernet_packet.set_ethertype(EtherTypes::Ipv6);

    // Create IPv6 packet
    let mut ipv6_buffer = vec![0u8; 40 + total_icmpv6_size];
    let mut ipv6_packet = MutableIpv6Packet::new(&mut ipv6_buffer)
        .ok_or("Failed to create IPv6 packet")?;

    // Set IPv6 header
    ipv6_packet.set_version(6);
    ipv6_packet.set_traffic_class(0);
    ipv6_packet.set_flow_label(0);
    ipv6_packet.set_payload_length(total_icmpv6_size as u16);
    ipv6_packet.set_next_header(pnet::packet::ip::IpNextHeaderProtocols::Icmpv6);
    ipv6_packet.set_hop_limit(255); // RFC 4861 requirement
    
    // Source: link-local address or unspecified
    let source_ip = Ipv6Addr::UNSPECIFIED;
    ipv6_packet.set_source(source_ip);
    
    // Destination: all routers multicast (ff02::2)
    let dest_ip = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
    ipv6_packet.set_destination(dest_ip);

    // Create ICMPv6 packet manually in a buffer
    let mut icmpv6_buffer = vec![0u8; total_icmpv6_size];
    
    // Set basic ICMPv6 Router Solicitation header
    icmpv6_buffer[0] = 133; // Type: Router Solicitation
    icmpv6_buffer[1] = 0;   // Code: 0
    icmpv6_buffer[2] = 0;   // Checksum: will be calculated later
    icmpv6_buffer[3] = 0;   // Checksum
    // Bytes 4-7 are reserved (already zero)
    
    // Add Source Link-layer Address option if requested
    if include_slla {
        icmpv6_buffer[8] = 1;  // Option Type: Source Link-layer Address
        icmpv6_buffer[9] = 1;  // Option Length: 1 (8 bytes)
        
        // Copy MAC address (6 bytes) starting at offset 10
        let mac_bytes = [
            source_mac.0, source_mac.1, source_mac.2,
            source_mac.3, source_mac.4, source_mac.5
        ];
        icmpv6_buffer[10..16].copy_from_slice(&mac_bytes);
        // Bytes 16-17 are padding (already zeroed)
    }

    // Calculate and set ICMPv6 checksum
    let mut icmpv6_packet = MutableIcmpv6Packet::new(&mut icmpv6_buffer)
        .ok_or("Failed to create ICMPv6 packet from buffer")?;
    
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
fn send_rs_packet(interface: &AppNetworkInterface, include_slla: bool) -> Result<(), Box<dyn std::error::Error>> {
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

        // Set hop limit to 255 (required by RFC 4861)
        let hop_limit: i32 = 255;
        let result = setsockopt(
            socket,
            IPPROTO_IPV6,
            IPV6_UNICAST_HOPS,
            &hop_limit as *const _ as *const i8,
            mem::size_of::<i32>() as i32,
        );
        if result != 0 {
            closesocket(socket);
            WSACleanup();
            return Err("Failed to set hop limit to 255".into());
        }

        // Calculate packet size
        let base_size = 8; // Basic RS header (4 bytes) + reserved (4 bytes)
        let slla_option_size = if include_slla { 8 } else { 0 };
        let total_size = base_size + slla_option_size;

        // Create Router Solicitation packet with optional Source Link-layer Address
        let mut packet = vec![0u8; total_size];
        
        // ICMPv6 header
        packet[0] = 133; // Router Solicitation type
        packet[1] = 0;   // Code
        packet[2] = 0;   // Checksum (kernel will calculate)
        packet[3] = 0;   // Checksum
        // Bytes 4-7 are reserved (already zero)

        // Add Source Link-layer Address option if requested
        if include_slla {
            // Parse MAC address from interface
            if let Some(mac_str) = &interface.mac {
                let mac_parts: Vec<&str> = mac_str.split(':').collect();
                if mac_parts.len() == 6 {
                    packet[8] = 1;  // Option Type: Source Link-layer Address
                    packet[9] = 1;  // Option Length: 1 (8 bytes)
                    
                    // Parse and copy MAC address
                    for (i, part) in mac_parts.iter().enumerate() {
                        if let Ok(byte) = u8::from_str_radix(part, 16) {
                            packet[10 + i] = byte;
                        }
                    }
                    // Bytes 16-17 would be padding if needed (already zero)
                }
            }
        }

        // Destination address: ff02::2 (All Routers multicast)
        let mut dest_addr: SOCKADDR_IN6 = mem::zeroed();
        dest_addr.sin6_family = AF_INET6 as u16;
        dest_addr.sin6_port = 0;
        dest_addr.sin6_flowinfo = 0;
        
        // Set IPv6 address to ff02::2
        let addr_ptr = &mut dest_addr.sin6_addr as *mut _ as *mut [u8; 16];
        (*addr_ptr)[0] = 0xff;
        (*addr_ptr)[1] = 0x02;
        (*addr_ptr)[15] = 0x02;
        
        // Set scope ID for interface binding
        let scope_ptr = &mut dest_addr.u as *mut _ as *mut u32;
        *scope_ptr = interface.index;

        // Send the packet
        let result = sendto(
            socket,
            packet.as_ptr() as *const i8,
            packet.len() as i32,
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
