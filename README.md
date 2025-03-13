# DNS Benchmark Tool

## Overview

The DNS Benchmark Tool is a powerful Python script that helps you analyze and compare the performance of different DNS (Domain Name System) providers. This tool provides comprehensive insights into DNS resolution speed, reliability, and geographic routing across multiple popular DNS services.

## Features

- 📊 Benchmark multiple DNS providers simultaneously
- 🌐 Test against popular global domains
- ⏱️ Measure DNS resolution times (A, AAAA, MX records)
- 🗺️ Trace network routes to DNS servers
- 📍 Visualize DNS server locations
- 📈 Generate performance charts
- 🌍 Create interactive traceroute map

### Supported DNS Providers

- System Default
- Google DNS
- Cloudflare DNS
- Quad9
- OpenDNS
- AdGuard DNS
- CleanBrowsing
- Comodo Secure DNS
- Level3 DNS
- Custom DNS (user-defined)

## Prerequisites

- Python 3.7+
- The following Python libraries (automatically installed):
  - dnspython
  - requests
  - matplotlib
  - numpy
  - folium
  - rich

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/dns-benchmark-tool.git
   cd dns-benchmark-tool
   ```

2. (Optional) Create a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
   ```

3. The script will automatically install required dependencies when first run.

## Usage

Run the script with:

```bash
python dns-benchmark.py
```

The tool will guide you through the process:
1. Option to add custom DNS servers
2. Select which DNS providers to test
3. Perform benchmarks
4. Display results
5. Generate optional visualizations:
   - Response time chart
   - Interactive traceroute map

### Example Workflow

```
DNS Benchmark Tool
This tool will compare your current DNS with popular providers.

Do you want to add custom DNS to test? (y/n): n

Select the DNS providers to test
1. System Default
2. Google
3. Cloudflare
...

Starting benchmark...
[Benchmark results displayed]

Generate the response time chart? (y/n): y
Generate the traceroute map? (y/n): y
```

## Outputs

The tool generates several output files:
- `dns_benchmark_response_times_YYYYMMDD_HHMMSS.png`: Bar chart of DNS response times
- `dns_traceroute_map_YYYYMMDD_HHMMSS.html`: Interactive map showing network routes

## Compatibility

- Supports Windows, macOS, and Linux
- Requires administrative/root privileges for traceroute functionality

## Limitations

- Internet connection required for geolocation and DNS resolution
- Traceroute results may vary based on network conditions
- Some firewalls might block traceroute attempts

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT LICENSE

## Disclaimer

This tool is for educational and diagnostic purposes. Always consult with network professionals for critical network configurations.
