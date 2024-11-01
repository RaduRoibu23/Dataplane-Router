# Simple Router Application

A C-based application that simulates a basic router, processing network packets through multiple protocols including IP and ARP.

---

## Features

- **Routing**: Implements a longest prefix match function to determine the output interface of IP packets. The `longestPrefixMatch` function searches a routing table to find the best match for a packet's destination IP address.
- **ARP (Address Resolution Protocol)**: Responds to ARP requests and sends ARP requests to discover MAC addresses on the network. The `arp_entry_function` searches an ARP table to find the MAC address associated with a given IP address.

---

## Project Structure

**Directories**:
- **include/**: Contains header files for various functionalities.
  - `lib.h`: Declares functions for hardware address conversion, route table reading, ARP table parsing, and initialization.
  - `list.h`, `protocols.h`, `queue.h`: Headers for list, protocol, and queue functionalities.
- **lib/**: Contains implementation files.
  - `lib.c`: Implements functions declared in `lib.h`.
  - `list.c`, `queue.c`: Implementations for list and queue functionalities.
- **router.c**: Main source file for the router application.
- **Makefile**: Build script for compiling the project.

**Files**:
- `README.md`: Project documentation.

---

## Building and Running the Project

1. **Build**: To compile the project, run:
   ```sh
   make
   ```
   This command will compile the source files and generate the router executable.

2. **Run**: To execute the router with predefined routing tables and interfaces, use:
   ```sh
   make run_router0
   make run_router1
   ```

---

## Key Functions

**lib.h**
- `int hwaddr_aton(const char *txt, uint8_t *addr)`: Converts a MAC address string to a byte array.
- `int read_rtable(const char *path, struct route_table_entry *rtable)`: Populates a route table from a file.
- `int parse_arp_table(char *path, struct arp_table_entry *arp_table)`: Parses a static ARP table from a file.
- `void init(int argc, char *argv[])`: Initializes the router.

**router.c**
- `struct route_table_entry *longestPrefixMatch(uint32_t ip, int rt_len, struct route_table_entry *route_table)`: Finds the best matching route for an IP address.
- `uint8_t *arp_entry_function(uint32_t ip, int arp_len, struct arp_table_entry *arp_table)`: Finds the MAC address for an IP address in the ARP table.
- `int main(int argc, char *argv[])`: Initializes the router, reads routing and ARP tables, and processes incoming packets.

---

## License

This project is licensed under the MIT License. See the LICENSE file for more details.
