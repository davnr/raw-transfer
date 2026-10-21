# raw_transfer: High-Performance Raw L2 File Transfer

`raw_transfer` is a blazingly fast, modular, point-to-point file and directory transfer utility for Linux. It operates **strictly at OSI Layer 2 (Data Link)**, bypassing the entire TCP/IP stack. 

Built with C and featuring an integrated Ncurses Text User Interface (TUI), it utilizes Raw Sockets, Zero-Copy memory mapping, and vectorized I/O to achieve maximum throughput on local networks.

---

## ✨ Key Features

* **TCP/IP Bypass**: Uses `AF_PACKET` raw sockets and a custom Ethertype (`0x88B5`) to send Ethernet frames directly over the wire.
* **Extreme Performance**:
  * **Vectorized I/O**: Utilizes `sendmmsg` and `recvmmsg` to send/receive batches of up to 256 packets in a single system call.
  * **Zero-Copy Receiving**: Reconstructs files directly into disk-mapped RAM using `mmap`, letting the Linux kernel handle background disk I/O.
  * **Jumbo Frames**: Automatically attempts to negotiate MTU 9000 for massive payload delivery with minimal overhead.
* **Custom ARQ Protocol**: Implements a highly efficient NACK-based (Negative Acknowledgement) recovery system for missing frames using bitmaps.
* **Integrated Directory Archiving**: Safely compresses folders on-the-fly. Uses `fork()` and `execvp()` to execute `tar` natively, ensuring **100% immunity to Shell Injection**.
* **Non-Blocking TUI**: A responsive file browser and transfer dashboard built with `ncurses` running at ~60 FPS.

---

## 🛠️ Architecture

The project follows a clean, modular MVC-like architecture:
* **`main.c`**: UI orchestrator and event loop.
* **`sender_engine.c` / `receiver_engine.c`**: Independent state machines handling the high-speed data planes and protocol logic.
* **`network_core.c`**: Raw socket setup, interface discovery, and MTU negotiation.
* **`system_utils.c`**: Precision timing, safe sub-process execution, and signal handling.

---

## 📦 Prerequisites

This software is designed exclusively for **Linux** systems.

* `gcc` 
* `make`
* `libncurses-dev` (or `ncurses-devel` on RHEL/Fedora)

**Debian Installation:**
```bash
sudo apt update && sudo apt install -y build-essential libncurses-dev
```

---

## 🚀 Building the Project

The project includes a `Makefile` that automatically handles out-of-source builds.

```bash

# Enter in /code/
cd code

# Compile the application (binaries will be placed in /bin/)
make
```

---

## 🎮 Usage

Because `raw-transfer` uses Raw Sockets (`SOCK_RAW`), it requires elevated privileges to run. You can run it via `sudo` or grant the executable network capabilities.

**Option 1: Using `sudo`**
```bash
sudo ./bin/raw-transfer
```

**Option 2: Using Linux Capabilities (Recommended)**
```bash
sudo setcap cap_net_raw+ep ./bin/raw-transfer
./bin/raw-transfer
```

### Transfer Workflow:
1. **Receiver:** Select the network interface, press **[ENTER]**, then press **[R]** to listen.
2. **Sender:** Select the network interface, press **[ENTER]**, then press **[I]** to open the file browser.
3. **Sender:** Navigate to the desired file or folder, press **[ENTER]** (or **[S]** for folders) to start the transfer.

---

## 🧪 Local Testing (Virtual Interfaces)

You can test the application on a single machine without needing two physical network cards by creating a virtual Ethernet (`veth`) pair.

**1. Setup the virtual network:**
```bash
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 up
sudo ip link set veth1 up
```

**2. Run the Receiver (Terminal 1):**
```bash
sudo ./bin/raw-transfer
# Select 'veth0' -> Press R
```

**3. Run the Sender (Terminal 2):**
```bash
sudo ./bin/raw-transfer
# Select 'veth1' -> Press I -> Select a file to send
```

**4. Cleanup:**
```bash
sudo ip link delete veth0
```

---

## ⚠️ Limitations & Network Constraints

* **No Routing**: Because this operates at Layer 2 (MAC addresses), it **cannot cross routers**. Both machines must be on the same physical switch or broadcast domain.
* **Wi-Fi Restrictions**: Injecting custom L2 frames into 802.11 (Wi-Fi) interfaces often fails unless the card is in monitor mode. The TUI automatically hides wireless interfaces to prevent driver-level drops. **Use Ethernet or Virtual Interfaces.**
