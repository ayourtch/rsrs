# RSRS - Router Solicitation/Advertisement Tool

A cross-platform GUI application for sending IPv6 Router Solicitation (RS) and Router Advertisement (RA) packets. This tool is useful for network testing, IPv6 troubleshooting, and testing first hop security features like RA Guard.

The name "RSRS" stands for **R**outer **S**olicitation/**R**outer **A**dvertisement **S**ender.

## Features

- **Cross-platform**: Supports macOS, Windows, and Linux
- **Network Interface Selection**: Choose from available network interfaces with refresh capability
- **Packet Types**: Send Router Solicitation or Router Advertisement packets
- **RFC 4861 Compliant**: Proper hop limit (255) and packet formatting
- **Source Link-layer Address Option**: Optional inclusion of MAC address in packets
- **Security Testing**: Test RA Guard and other first hop security features
- **Real-time Status**: Visual feedback for packet sending operations

## Prerequisites

### Development Environment

You need Rust installed on your system. Install it from [rustup.rs](https://rustup.rs/):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

### Platform-Specific Requirements

#### macOS

No additional packages required beyond Rust. The application uses the `pnet` library which works with macOS's built-in networking APIs.

#### Linux

Install development packages for raw socket support:

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install build-essential pkg-config libpcap-dev
```

**RHEL/CentOS/Fedora:**
```bash
# RHEL/CentOS
sudo yum install gcc pkg-config libpcap-devel
# Or for newer versions
sudo dnf install gcc pkg-config libpcap-devel

# Fedora
sudo dnf install gcc pkg-config libpcap-devel
```

**Arch Linux:**
```bash
sudo pacman -S base-devel pkg-config libpcap
```

#### Windows (Cross-compilation from macOS/Linux)

For cross-compiling to Windows from macOS:

```bash
# Install mingw-w64 toolchain
brew install mingw-w64

# Add Windows target to Rust
rustup target add x86_64-pc-windows-gnu
```

For cross-compiling to Windows from Linux:

```bash
# Ubuntu/Debian
sudo apt install gcc-mingw-w64-x86-64

# RHEL/CentOS/Fedora
sudo dnf install mingw64-gcc

# Add Windows target to Rust
rustup target add x86_64-pc-windows-gnu
```

## Building

### Clone the Repository

```bash
git clone <repository-url>
cd rsrs
```

### Native Compilation

#### For Current Platform (macOS/Linux)

```bash
cargo build --release
```

The binary will be located at:
- `target/release/rsrs` (macOS/Linux)

#### Cross-compilation for Windows

From macOS:
```bash
cargo build --target x86_64-pc-windows-gnu --release
```

From Linux:
```bash
cargo build --target x86_64-pc-windows-gnu --release
```

The Windows executable will be located at:
- `target/x86_64-pc-windows-gnu/release/rsrs.exe`

### Running During Development

```bash
cargo run
```

## Installation

### macOS/Linux

Copy the binary to a location in your PATH:

```bash
# Option 1: User-local installation
cp target/release/rsrs ~/.local/bin/

# Option 2: System-wide installation (requires sudo)
sudo cp target/release/rsrs /usr/local/bin/
```

### Windows

Copy the `.exe` file to your desired location and optionally add it to your PATH.

## Usage

### Running the Application

#### macOS/Linux
```bash
# If installed in PATH
rsrs

# Or run directly
./target/release/rsrs
```

#### Windows
```cmd
rsrs.exe
```

### Required Privileges

**⚠️ Important: This application requires elevated privileges to send raw packets.**

#### macOS/Linux
```bash
sudo ./rsrs
```

#### Windows
Run as Administrator:
1. Right-click on `rsrs.exe`
2. Select "Run as Administrator"

### Application Interface

1. **Network Interface Selection**
   - Choose from the dropdown list of available interfaces
   - Click the 🔄 button to refresh the interface list
   - Interface details (MAC, IPs) are shown when selected

2. **Packet Type Selection**
   - **Router Solicitation**: For discovering IPv6 routers (safe)
   - **Router Advertisement**: For testing security features (⚠️ may trigger alerts)

3. **Options**
   - **Include Source Link-layer Address option**: Adds your MAC address to the packet

4. **Send Packet**
   - Click the appropriate button to send the selected packet type
   - Status messages will show success/failure

## Packet Details

### Router Solicitation (Type 133)
- **Source**: `::` (unspecified address)
- **Destination**: `ff02::2` (All Routers multicast)
- **Hop Limit**: 255 (RFC 4861 requirement)
- **Optional SLLA**: Include sender's MAC address

### Router Advertisement (Type 134)
- **Source**: Link-local address (for testing)
- **Destination**: `ff02::1` (All Nodes multicast)  
- **Hop Limit**: 255 (RFC 4861 requirement)
- **Router Lifetime**: 0 (indicates not a real router)
- **Optional SLLA**: Include sender's MAC address

## Security Considerations

### Router Advertisement Warnings

**⚠️ Sending Router Advertisements may trigger security alerts!**

Router Advertisements are used by legitimate routers to advertise network prefixes and routing information. Sending unauthorized RAs can:

- Trigger RA Guard on managed switches
- Generate security alerts in network monitoring systems
- Be blocked by first hop security features
- Potentially disrupt network operations in misconfigured environments

### Legitimate Use Cases

This tool is designed for:
- **Network Testing**: Verify IPv6 neighbor discovery works
- **Security Testing**: Test RA Guard and similar protections
- **Troubleshooting**: Debug IPv6 connectivity issues
- **Education**: Learn about IPv6 neighbor discovery protocol

### Responsible Usage

- Only use on networks you own or have explicit permission to test
- Coordinate with network administrators before testing RA functionality
- Monitor for security alerts when testing RA Guard
- Use Router Lifetime = 0 to minimize impact (already set in this tool)

## Troubleshooting

### Permission Denied Errors

**Linux/macOS:**
```bash
# Ensure you're running with sudo
sudo ./rsrs
```

**Windows:**
- Run as Administrator
- Check Windows Defender settings
- Verify no antivirus is blocking raw socket access

### No Interfaces Shown

- Click the 🔄 refresh button
- Ensure network interfaces are up and running
- Try running with elevated privileges
- Check that IPv6 is enabled on your interfaces

### Compilation Errors

**Missing development tools:**
```bash
# macOS - install Xcode command line tools
xcode-select --install

# Linux - install build essentials (see Prerequisites section)
```

**Cross-compilation issues:**
- Ensure mingw-w64 is properly installed
- Verify the Windows target is added: `rustup target list --installed`
- Check that the correct toolchain is in PATH

### Runtime Errors

**"Failed to create raw socket":**
- Run with elevated privileges (sudo/Administrator)
- Check that raw socket creation is not blocked by security software

**"Interface not found":**
- Refresh the interface list
- Ensure the selected interface is still available and up

## Building from Source

### Dependencies

The application uses these main Rust crates:

- `eframe` - GUI framework
- `egui` - Immediate mode GUI library  
- `pnet` - Packet manipulation (Unix platforms)
- `windows` - Windows API bindings (Windows only)
- `winapi` - Windows API bindings (Windows only)

### Development

```bash
# Run in development mode
cargo run

# Run tests
cargo test

# Check for common issues
cargo clippy

# Format code
cargo fmt
```

## License

MIT

## Acknowledgments

- Built with [egui](https://github.com/emilk/egui) for the GUI
- Uses [pnet](https://github.com/libpnet/libpnet) for packet manipulation on Unix systems
- Implements RFC 4861 (Neighbor Discovery for IPv6)
