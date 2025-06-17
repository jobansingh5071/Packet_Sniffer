## 🔍 CLI Filters

The sniffer supports optional CLI arguments for filtering:

- `--ip`: Filter packets by source or destination IP.
- `--protocol`: Filter by protocol (TCP, UDP, ICMP).
- `--port`: Filter by port (either source or destination).

### Examples

```bash
# Capture only TCP packets
python sniffer.py --protocol TCP

# Capture traffic from/to a specific IP
python sniffer.py --ip 10.0.0.2

# Capture packets involving port 80
python sniffer.py --port 80

# Combine all filters
python sniffer.py --ip 192.168.1.10 --protocol UDP --port 53
