use eframe::egui;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types, Icmpv6Code, MutableIcmpv6Packet};
use pnet::packet::ipv6::{MutableIpv6Packet, Ipv6Packet};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::net::Ipv6Addr;
use std::sync::mpsc;
use std::thread;

#[derive(Default)]
struct RouterSolicitationApp {
    interfaces: Vec<NetworkInterface>,
    selected_interface: Option<usize>,
    status_message: String,
    message_receiver: Option<mpsc::Receiver<String>>,
}

impl RouterSolicitationApp {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let interfaces = datalink::interfaces()
            .into_iter()
            .filter(|iface| !iface.is_loopback() && iface.is_up())
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
                               interface.mac.map_or("No MAC".to_string(), |mac| mac.to_string()))
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
                                interface.mac.map_or("No MAC".to_string(), |mac| mac.to_string())
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
                    ui.monospace(format!("MAC: {}", interface.mac.map_or("None".to_string(), |mac| mac.to_string())));
                    ui.monospace(format!("IPs: {}", 
                        interface.ips.iter()
                            .map(|ip| ip.ip().to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
            }
        });

        // Request repaint to check for messages
        ctx.request_repaint();
    }
}

fn send_rs_packet(interface: &NetworkInterface) -> Result<(), Box<dyn std::error::Error>> {
    // Create a channel to send packets
    let (mut tx, _rx) = match datalink::channel(interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err("Unsupported channel type".into()),
        Err(e) => return Err(format!("Failed to create channel: {}", e).into()),
    };

    // Get the interface MAC address
    let source_mac = interface.mac.ok_or("Interface has no MAC address")?;
    
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
    tx.send_to(ethernet_packet.packet(), Some(interface.clone()))
        .ok_or("Failed to send packet")?
        .map_err(|e| format!("Send error: {}", e))?;

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
