#!/usr/bin/env python3
"""
DNS Benchmark Tool

This script performs DNS resolution benchmarks against multiple DNS providers,
traces the network path to each DNS server, and visualizes the geographic proximity
of DNS servers to your location on a map.
"""

import os
import sys
import time
import socket
import ipaddress
import platform
import datetime
import concurrent.futures
import subprocess
import json
import statistics
from collections import defaultdict

try:
    import dns.resolver
    import dns.query
    import dns.message
    import requests
    import matplotlib.pyplot as plt
    import matplotlib.cm as cm
    from matplotlib.colors import Normalize
    import numpy as np
    import folium
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, TextColumn, BarColumn, TimeElapsedColumn
except ImportError:
    print("Missing required libraries. Installing them now...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", 
                         "dnspython", "requests", "matplotlib", 
                         "numpy", "folium", "rich"])
    print("Libraries installed successfully. Restarting script...")
    os.execv(sys.executable, [sys.executable] + sys.argv)

# Initialize console for rich output
console = Console()

class DNSBenchmark:
    def __init__(self):
        self.dns_servers = {
            "System Default": [],  # Will be detected automatically
            "Google": ["8.8.8.8", "8.8.4.4"],
            "Cloudflare": ["1.1.1.1", "1.0.0.1"],
            "Quad9": ["9.9.9.9", "149.112.112.112"],
            "OpenDNS": ["208.67.222.222", "208.67.220.220"],
            "AdGuard": ["94.140.14.14", "94.140.15.15"],
            "CleanBrowsing": ["185.228.168.9", "185.228.169.9"],
            "Comodo Secure": ["8.26.56.26", "8.20.247.20"],
            "Level3": ["4.2.2.1", "4.2.2.2"]
        }
        
        # Get the system's default DNS
        self.get_system_dns()
        
        # Test domains representing different categories and global CDNs
        self.test_domains = [
            "google.com",
            "facebook.com",
            "amazon.com",
            "netflix.com",
            "microsoft.com",
            "apple.com",
            "cloudflare.com",
            "akamai.com",
            "fastly.com",
            "cdn.jsdelivr.net"
        ]
        
        # Initialize results containers
        self.results = {}
        self.trace_results = {}
        self.locations = {}
        self.my_location = None

    def get_system_dns(self):
        """Detect system's default DNS servers"""
        try:
            # For Unix-like systems
            if platform.system() != "Windows":
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        if line.startswith('nameserver'):
                            self.dns_servers["System Default"].append(line.split()[1])
            else:
                # For Windows
                output = subprocess.check_output(
                    ["powershell", "-Command", 
                     "Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses"], 
                    text=True
                )
                for ip in output.strip().split('\n'):
                    if ip.strip():
                        self.dns_servers["System Default"].append(ip.strip())
                        
            # If no DNS servers were found, use a fallback method
            if not self.dns_servers["System Default"]:
                resolver = dns.resolver.Resolver()
                self.dns_servers["System Default"] = resolver.nameservers
                
            console.print(f"[green]System default DNS servers: {', '.join(self.dns_servers['System Default'])}")
            
        except Exception as e:
            console.print(f"[yellow]Warning: Could not detect system DNS servers: {e}")
            console.print("[yellow]Using localhost as fallback")
            self.dns_servers["System Default"] = ["127.0.0.1"]

    def is_valid_ip(self, ip):
        """Check if a string is a valid IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def get_my_location(self):
        """Get the approximate geographic location of the user"""
        try:
            response = requests.get("https://ipinfo.io/json", timeout=5)
            if response.status_code == 200:
                data = response.json()
                self.my_location = {
                    "ip": data.get("ip", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "region": data.get("region", "Unknown"),
                    "country": data.get("country", "Unknown"),
                    "loc": data.get("loc", "0,0")
                }
                console.print(f"[green]Your location: {self.my_location['city']}, {self.my_location['region']}, {self.my_location['country']}")
                return True
            else:
                console.print("[yellow]Warning: Could not determine your location. HTTP status:", response.status_code)
        except Exception as e:
            console.print(f"[yellow]Warning: Could not determine your location: {e}")
        
        # Fallback to a default location (0,0 coordinates)
        self.my_location = {
            "ip": "Unknown",
            "city": "Unknown",
            "region": "Unknown",
            "country": "Unknown",
            "loc": "0,0"
        }
        return False

    def is_private_ip(self, ip):
        """Check if an IP address is private"""
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def get_dns_server_location(self, ip):
        """Get the geographic location of a DNS server"""
        if ip in self.locations:
            return self.locations[ip]
            
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
            if response.status_code == 200:
                data = response.json()
                location = {
                    "ip": ip,
                    "hostname": data.get("hostname", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "region": data.get("region", "Unknown"),
                    "country": data.get("country", "Unknown"),
                    "org": data.get("org", "Unknown"),
                    "loc": data.get("loc", "0,0")
                }
                self.locations[ip] = location
                return location
            else:
                console.print(f"[yellow]Warning: Could not determine location for IP {ip}. HTTP status:", response.status_code)
        except Exception as e:
            console.print(f"[yellow]Warning: Could not determine location for IP {ip}: {e}")
        
        # Return a default location if lookup fails
        default_location = {
            "ip": ip,
            "hostname": "Unknown",
            "city": "Unknown",
            "region": "Unknown",
            "country": "Unknown",
            "org": "Unknown",
            "loc": "0,0"
        }
        self.locations[ip] = default_location
        return default_location

    def query_dns(self, dns_server, domain, query_type='A'):
        """Query a DNS server for a specific domain and record type"""
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]
        resolver.timeout = 2
        resolver.lifetime = 4
        
        try:
            start_time = time.time()
            answers = resolver.resolve(domain, query_type)
            end_time = time.time()
            
            response_time = (end_time - start_time) * 1000  # Convert to ms
            
            # Extract the answers
            records = [answer.to_text() for answer in answers]
            
            return {
                "status": "success",
                "response_time": response_time,
                "records": records
            }
        except dns.resolver.NXDOMAIN:
            return {
                "status": "nxdomain",
                "response_time": 0,
                "records": []
            }
        except dns.resolver.NoAnswer:
            return {
                "status": "noanswer",
                "response_time": 0,
                "records": []
            }
        except dns.resolver.Timeout:
            return {
                "status": "timeout",
                "response_time": 0,
                "records": []
            }
        except Exception as e:
            return {
                "status": "error",
                "response_time": 0,
                "records": [],
                "error": str(e)
            }

    def trace_route(self, target_ip):
        """Perform a traceroute to the DNS server"""
        hops = []
        
        # Determine the traceroute command based on platform
        if platform.system() == "Windows":
            cmd = ["tracert", "-d", "-h", "30", target_ip]
        else:
            cmd = ["traceroute", "-n", "-m", "30", target_ip]
        
        try:
            # Execute the traceroute command
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Parse the output
            line_count = 0
            for line in process.stdout:
                line_count += 1
                # Skip header lines (usually first one or two)
                if line_count <= 2 and "traceroute to" in line.lower():
                    continue
                
                # Process the trace line
                parts = line.strip().split()
                
                # Extract hop number and IP
                hop_num = None
                hop_ip = None
                response_time = None
                
                # Parse for different OS formats
                if platform.system() == "Windows":
                    # Windows format: 1  10 ms  10 ms  9 ms  192.168.1.1
                    if len(parts) >= 5 and parts[0].isdigit():
                        hop_num = int(parts[0])
                        # Find the first IP address in the line
                        for part in parts:
                            if self.is_valid_ip(part):
                                hop_ip = part
                                break
                        # Try to get response time
                        for i, part in enumerate(parts):
                            if part == "ms" and i > 0 and parts[i-1].replace('<', '').isdigit():
                                response_time = float(parts[i-1])
                                break
                else:
                    # Unix format: 1  192.168.1.1  0.432 ms  0.425 ms  0.367 ms
                    if len(parts) >= 2 and parts[0].isdigit():
                        hop_num = int(parts[0])
                        if self.is_valid_ip(parts[1]):
                            hop_ip = parts[1]
                        # Try to get response time
                        for i, part in enumerate(parts):
                            if part == "ms" and i > 0 and parts[i-1].replace('*', '').replace('<', '').replace(',', '.').replace('!', '').strip():
                                try:
                                    response_time = float(parts[i-1].replace(',', '.'))
                                    break
                                except ValueError:
                                    pass
                
                # Add valid hops to our list
                if hop_num is not None and hop_ip is not None and hop_ip != "*":
                    hops.append({
                        "hop": hop_num,
                        "ip": hop_ip,
                        "time": response_time
                    })
            
            process.wait(timeout=60)
            
            # Get location data for each hop
            for hop in hops:
                if self.is_valid_ip(hop["ip"]):
                    location = self.get_dns_server_location(hop["ip"])
                    hop["location"] = location
            
            return hops
            
        except subprocess.TimeoutExpired:
            process.kill()
            console.print(f"[yellow]Warning: Traceroute to {target_ip} timed out")
            return []
        except Exception as e:
            console.print(f"[yellow]Warning: Traceroute to {target_ip} failed: {e}")
            return []

    def benchmark_dns_server(self, dns_provider, dns_server):
        """Benchmark a single DNS server against all test domains"""
        results = {
            "provider": dns_provider,
            "server": dns_server,
            "queries": {}
        }
        
        # Query each test domain
        for domain in self.test_domains:
            # Test different record types
            for record_type in ['A', 'AAAA', 'MX']:
                # Perform multiple queries for more accurate timing
                query_times = []
                records = []
                status = "success"
                
                for _ in range(3):  # 3 queries per domain-record combination
                    query_result = self.query_dns(dns_server, domain, record_type)
                    
                    if query_result["status"] == "success":
                        query_times.append(query_result["response_time"])
                        if not records and query_result["records"]:
                            records = query_result["records"]
                    else:
                        status = query_result["status"]
                
                # Calculate statistics if we have successful queries
                if query_times:
                    avg_time = statistics.mean(query_times)
                    min_time = min(query_times)
                    max_time = max(query_times)
                    std_dev = statistics.stdev(query_times) if len(query_times) > 1 else 0
                else:
                    avg_time = min_time = max_time = std_dev = 0
                
                # Store results for this domain-record combination
                key = f"{domain}/{record_type}"
                results["queries"][key] = {
                    "status": status,
                    "avg_time": avg_time,
                    "min_time": min_time,
                    "max_time": max_time,
                    "std_dev": std_dev,
                    "records": records
                }
        
        # Get location data for this DNS server
        location = self.get_dns_server_location(dns_server)
        results["location"] = location
        
        return results

    def run_benchmark(self, custom_dns=None):
        """Run the benchmark against all DNS servers"""
        # Add custom DNS if provided
        if custom_dns:
            if isinstance(custom_dns, str):
                if self.is_valid_ip(custom_dns):
                    self.dns_servers["Custom"] = [custom_dns]
                else:
                    console.print(f"[red]Error: Invalid IP address: {custom_dns}")
                    return False
            elif isinstance(custom_dns, list):
                valid_ips = [ip for ip in custom_dns if self.is_valid_ip(ip)]
                if valid_ips:
                    self.dns_servers["Custom"] = valid_ips
                else:
                    console.print("[red]Error: No valid IP addresses in custom DNS list")
                    return False
            else:
                console.print("[red]Error: Custom DNS must be an IP address or a list of IP addresses")
                return False
        
        # Get user's location
        self.get_my_location()
        
        # Create a progress bar
        total_servers = sum(len(servers) for servers in self.dns_servers.values())
        total_steps = total_servers * (1 + len(self.test_domains) * 3)  # Benchmark + traceroute
        
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn()
        ) as progress:
            task = progress.add_task("[cyan]Running DNS benchmark...", total=total_steps)
            
            # Run benchmarks for each DNS provider
            for provider, servers in self.dns_servers.items():
                self.results[provider] = {}
                self.trace_results[provider] = {}
                
                for server in servers:
                    progress.update(task, description=f"[cyan]Benchmarking {provider} ({server})...")
                    
                    # Run the benchmark
                    result = self.benchmark_dns_server(provider, server)
                    self.results[provider][server] = result
                    progress.advance(task, len(self.test_domains) * 3)
                    
                    # Run traceroute
                    progress.update(task, description=f"[cyan]Tracing route to {provider} ({server})...")
                    trace = self.trace_route(server)
                    self.trace_results[provider][server] = trace
                    progress.advance(task, 1)
        
        return True

    def analyze_results(self):
        """Analyze the benchmark results"""
        # Calculate overall statistics
        stats = {}
        
        for provider, servers in self.results.items():
            provider_times = []
            provider_success = 0
            provider_total = 0
            
            for server, result in servers.items():
                server_times = []
                server_success = 0
                server_total = 0
                
                for query, query_result in result["queries"].items():
                    if query_result["status"] == "success":
                        server_times.append(query_result["avg_time"])
                        server_success += 1
                        provider_times.append(query_result["avg_time"])
                        provider_success += 1
                    
                    server_total += 1
                    provider_total += 1
                
                # Calculate server statistics
                if server_times:
                    avg_time = statistics.mean(server_times)
                    min_time = min(server_times)
                    max_time = max(server_times)
                    reliability = (server_success / server_total) * 100
                else:
                    avg_time = min_time = max_time = reliability = 0
                
                # Store server statistics
                if provider not in stats:
                    stats[provider] = {"servers": {}}
                
                stats[provider]["servers"][server] = {
                    "avg_time": avg_time,
                    "min_time": min_time,
                    "max_time": max_time,
                    "reliability": reliability,
                    "success": server_success,
                    "total": server_total
                }
            
            # Calculate provider statistics
            if provider_times:
                avg_time = statistics.mean(provider_times)
                min_time = min(provider_times)
                max_time = max(provider_times)
                reliability = (provider_success / provider_total) * 100
            else:
                avg_time = min_time = max_time = reliability = 0
            
            stats[provider]["avg_time"] = avg_time
            stats[provider]["min_time"] = min_time
            stats[provider]["max_time"] = max_time
            stats[provider]["reliability"] = reliability
            stats[provider]["success"] = provider_success
            stats[provider]["total"] = provider_total
        
        return stats

    def display_results(self, stats):
        """Display benchmark results in a tabular format"""
        # Create a table for provider summary
        provider_table = Table(title="DNS Provider Performance Summary")
        provider_table.add_column("Provider", style="cyan")
        provider_table.add_column("Avg Response (ms)", justify="right")
        provider_table.add_column("Min (ms)", justify="right")
        provider_table.add_column("Max (ms)", justify="right")
        provider_table.add_column("Reliability (%)", justify="right")
        provider_table.add_column("Location", style="green")
        
        # Sort providers by average response time
        sorted_providers = sorted(stats.keys(), key=lambda p: stats[p]["avg_time"] if stats[p]["avg_time"] > 0 else float('inf'))
        
        for provider in sorted_providers:
            provider_stats = stats[provider]
            
            # Get location info - use the first server's location
            location_info = "Unknown"
            for server in self.results[provider]:
                if "location" in self.results[provider][server]:
                    loc = self.results[provider][server]["location"]
                    location_info = f"{loc['city']}, {loc['country']}"
                    break
            
            # Add row to the table
            provider_table.add_row(
                provider,
                f"{provider_stats['avg_time']:.2f}",
                f"{provider_stats['min_time']:.2f}",
                f"{provider_stats['max_time']:.2f}",
                f"{provider_stats['reliability']:.1f}",
                location_info
            )
        
        console.print(provider_table)
        
        # Create a table for server details
        server_table = Table(title="DNS Server Performance Details")
        server_table.add_column("Provider", style="cyan")
        server_table.add_column("Server IP", style="blue")
        server_table.add_column("Avg Response (ms)", justify="right")
        server_table.add_column("Reliability (%)", justify="right")
        server_table.add_column("Hops", justify="right")
        server_table.add_column("Location", style="green")
        
        for provider in sorted_providers:
            provider_stats = stats[provider]
            
            # Sort servers by average response time
            sorted_servers = sorted(
                provider_stats["servers"].keys(), 
                key=lambda s: provider_stats["servers"][s]["avg_time"] if provider_stats["servers"][s]["avg_time"] > 0 else float('inf')
            )
            
            for server in sorted_servers:
                server_stats = provider_stats["servers"][server]
                
                # Get hop count from trace_results
                hop_count = "N/A"
                if provider in self.trace_results and server in self.trace_results[provider]:
                    hop_count = str(len(self.trace_results[provider][server]))
                
                # Get location info
                location_info = "Unknown"
                if "location" in self.results[provider][server]:
                    loc = self.results[provider][server]["location"]
                    location_info = f"{loc['city']}, {loc['country']}"
                
                # Add row to the table
                server_table.add_row(
                    provider,
                    server,
                    f"{server_stats['avg_time']:.2f}",
                    f"{server_stats['reliability']:.1f}",
                    hop_count,
                    location_info
                )
        
        console.print(server_table)
        
        # Display recommendation
        self.display_recommendation(stats, sorted_providers)
    
    def display_recommendation(self, stats, sorted_providers):
        """Display a recommendation based on the benchmark results"""
        # Find the best provider based on a combination of performance and reliability
        best_provider = None
        best_score = float('inf')
        
        for provider in sorted_providers:
            provider_stats = stats[provider]
            if provider_stats["avg_time"] > 0:
                # Calculate a score (lower is better)
                # Weight: 80% response time, 20% reliability
                score = (provider_stats["avg_time"] * 0.8) - (provider_stats["reliability"] * 0.2)
                
                if score < best_score:
                    best_score = score
                    best_provider = provider
        
        console.print("\n[bold green]Recommendation:[/bold green]")
        
        if best_provider and best_provider != "System Default":
            system_stats = stats.get("System Default", {"avg_time": 0, "reliability": 0})
            
            # Compare with system default
            if system_stats["avg_time"] > 0:
                speed_diff = ((system_stats["avg_time"] - stats[best_provider]["avg_time"]) / system_stats["avg_time"]) * 100
                
                if speed_diff > 10:  # At least 10% faster
                    console.print(f"[green]Switching to {best_provider} could improve your DNS resolution speed by approximately {speed_diff:.1f}%.")
                    console.print(f"[green]This could result in faster initial connection times to websites and services.")
                else:
                    console.print(f"[yellow]Your current DNS performs well. Switching to {best_provider} would only provide a minor improvement of {speed_diff:.1f}%.")
            else:
                console.print(f"[green]The {best_provider} DNS provider showed the best overall performance in our tests.")
                
            # Display the server IPs
            if best_provider in self.dns_servers:
                server_ips = ", ".join(self.dns_servers[best_provider])
                console.print(f"[green]To use {best_provider}, configure your DNS servers to: {server_ips}")
        else:
            console.print("[yellow]Your current system DNS servers are already performing optimally compared to the alternatives we tested.")

    def plot_response_times(self):
        """Create a bar chart of average response times"""
        # Collect data for plotting
        providers = []
        avg_times = []
        
        # Calculate overall averages for each provider
        for provider, servers in self.results.items():
            all_times = []
            
            for server, result in servers.items():
                for query, query_result in result["queries"].items():
                    if query_result["status"] == "success":
                        all_times.append(query_result["avg_time"])
            
            if all_times:
                providers.append(provider)
                avg_times.append(statistics.mean(all_times))
        
        # Sort by average time
        sorted_data = sorted(zip(providers, avg_times), key=lambda x: x[1])
        providers = [x[0] for x in sorted_data]
        avg_times = [x[1] for x in sorted_data]
        
        # Create the plot
        plt.figure(figsize=(10, 6))
        bars = plt.bar(providers, avg_times, color='skyblue')
        
        # Add value labels above bars
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height + 1,
                    f'{height:.1f} ms',
                    ha='center', va='bottom', rotation=0)
        
        plt.title('Average DNS Response Time by Provider')
        plt.xlabel('DNS Provider')
        plt.ylabel('Average Response Time (ms)')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        
        # Save the plot
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"dns_benchmark_response_times_{timestamp}.png"
        plt.savefig(filename)
        console.print(f"[green]Response time chart saved as: {filename}")
        
        # Show the plot
        plt.show()

    def create_traceroute_map(self):
        """Create an interactive map showing the traceroute paths"""
        # Skip if no location data
        if not self.my_location:
            console.print("[yellow]Warning: Could not create traceroute map - location data unavailable")
            return
        
        # Create a map centered on user's location
        user_lat, user_lon = self.my_location["loc"].split(",")
        m = folium.Map(location=[float(user_lat), float(user_lon)], zoom_start=4)
        
        # Add a marker for the user's location
        folium.Marker(
            [float(user_lat), float(user_lon)],
            popup=f"Your Location: {self.my_location['city']}, {self.my_location['country']}",
            icon=folium.Icon(color='green', icon='home')
        ).add_to(m)
        
        # Assign colors to different providers
        providers = list(self.dns_servers.keys())
        colors = cm.rainbow(np.linspace(0, 1, len(providers)))
        provider_colors = {provider: f'#{int(r*255):02x}{int(g*255):02x}{int(b*255):02x}' 
                          for provider, (r, g, b, _) in zip(providers, colors)}
        
        # Track DNS server markers to avoid duplicates
        dns_markers = set()
        
        # For each provider and server
        for provider, servers in self.dns_servers.items():
            color = provider_colors.get(provider, '#3388ff')
            
            for server in servers:
                if server in self.trace_results.get(provider, {}):
                    hops = self.trace_results[provider][server]
                    
                    # Get server location
                    server_location = None
                    if provider in self.results and server in self.results[provider]:
                        if "location" in self.results[provider][server]:
                            server_location = self.results[provider][server]["location"]
                    
                    # Skip if we don't have location data for the server
                    if not server_location or "," not in server_location.get("loc", ""):
                        continue
                    
                    server_lat, server_lon = server_location["loc"].split(",")
                    
                    # Create marker for DNS server if not already added
                    if self.is_private_ip(server):
                        # For private IPs, place near user location with a small offset
                        marker_position = [float(user_lat) + 0.1, float(user_lon) + 0.1]
                        marker_key = f"private-{server}"
                        
                        if marker_key not in dns_markers:
                            dns_markers.add(marker_key)
                            
                            # Get response time info
                            avg_time = "N/A"
                            if provider in self.results and server in self.results[provider]:
                                times = []
                                for query, result in self.results[provider][server]["queries"].items():
                                    if result["status"] == "success":
                                        times.append(result["avg_time"])
                                if times:
                                    avg_time = f"{statistics.mean(times):.1f} ms"
                            
                            # Add the server marker with different style for local DNS
                            folium.Marker(
                                marker_position,
                                popup=f"{provider} DNS: {server}<br>Network: Rete Privata Locale<br>Avg. Response: {avg_time}",
                                icon=folium.Icon(color='blue', icon='wifi')
                            ).add_to(m)
                    else:
                        # For public IPs, continue with normal handling
                        marker_key = f"{server_lat},{server_lon},{server}"
                        if marker_key not in dns_markers:
                            dns_markers.add(marker_key)
                            
                            # Get response time info
                            avg_time = "N/A"
                            if provider in self.results and server in self.results[provider]:
                                times = []
                                for query, result in self.results[provider][server]["queries"].items():
                                    if result["status"] == "success":
                                        times.append(result["avg_time"])
                                if times:
                                    avg_time = f"{statistics.mean(times):.1f} ms"
                            
                            # Add the server marker
                            folium.Marker(
                                [float(server_lat), float(server_lon)],
                                popup=f"{provider} DNS: {server}<br>Location: {server_location['city']}, {server_location['country']}<br>Avg. Response: {avg_time}",
                                icon=folium.Icon(color='red', icon='server')
                            ).add_to(m)
                    
                    # Create polylines for each hop in the trace with known locations
                    last_lat, last_lon = float(user_lat), float(user_lon)
                    
                    for hop in hops:
                        if "location" in hop and "loc" in hop["location"] and "," in hop["location"]["loc"]:
                            hop_lat, hop_lon = hop["location"]["loc"].split(",")
                            
                            try:
                                hop_lat = float(hop_lat)
                                hop_lon = float(hop_lon)
                            except ValueError:
                                continue

                            if hop_lat == 0.0 and hop_lon == 0.0:
                                
                                continue
                            # Draw a line from the previous hop to this one
                            folium.PolyLine(
                                [(last_lat, last_lon), (float(hop_lat), float(hop_lon))],
                                color=color,
                                weight=2,
                                opacity=0.7,
                                tooltip=f"Hop {hop['hop']}: {hop['ip']} ({hop['location']['city']}, {hop['location']['country']})"
                            ).add_to(m)
                            
                            # Update for the next segment
                            last_lat, last_lon = float(hop_lat), float(hop_lon)
                    
                    # If we have both user and server location, create a direct line for comparison
                    if server_location and "loc" in server_location:
                        server_lat, server_lon = server_location["loc"].split(",")
                        
                        try:
                            server_lat = float(server_lat)
                            server_lon = float(server_lon)
                        except ValueError:
                            continue
                        
                        # Skip if private IP or if coordinates = (0,0)
                        if self.is_private_ip(server) or (server_lat == 0.0 and server_lon == 0.0):
                            continue

                        folium.PolyLine(
                            [(float(user_lat), float(user_lon)), (server_lat, server_lon)],
                            color=color,
                            weight=1,
                            opacity=0.4,
                            dash_array='5,5',
                            tooltip=f"Direct path to {provider} ({server})"
                        ).add_to(m)

        
        # Legend
        legend_html = '''
        <div style="position: fixed; 
                    bottom: 50px; left: 50px; width: 200px; height: auto;
                    border:2px solid grey; z-index:9999; font-size:14px;
                    background-color:white; padding: 10px;
                    border-radius: 5px;">
        <p><b>DNS Providers</b></p>
        '''
        
        for provider, color in provider_colors.items():
            legend_html += f'<p><span style="background-color:{color};display:inline-block;width:10px;height:10px;margin-right:5px;"></span>{provider}</p>'
        
        legend_html += '''
        <p><span style="color:green;font-size:18px;">&#8962;</span> Your Location</p>
        <p><span style="color:red;font-size:18px;">&#9783;</span> DNS Servers</p>
        <p><span style="color:blue;font-size:18px;">&#8776;</span> Local Network DNS</p>
        <p><hr style="margin:5px 0;"></p>
        <p style="font-size:12px;"><i>Solid lines: Actual network path<br>
        Dotted lines: Direct geographic path</i></p>
        </div>
        '''
        
        m.get_root().html.add_child(folium.Element(legend_html))
        
        # Save the map
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"dns_traceroute_map_{timestamp}.html"
        m.save(filename)
        console.print(f"[green]Traceroute map saved as: {filename}")
        
        # Try to open the map in a browser
        try:
            if platform.system() == 'Darwin':  # macOS
                subprocess.call(['open', filename])
            elif platform.system() == 'Windows':
                os.startfile(filename)
            else:  # linux variants
                subprocess.call(['xdg-open', filename])
        except Exception as e:
            console.print(f"[yellow]Info: Could not automatically open the map: {e}")
            console.print(f"[yellow]Please open {filename} in your web browser to view the traceroute map.")

    def add_custom_dns(self):
        """Allow the user to add custom DNS servers to test"""
        console.print("\n[bold cyan]Add Custom DNS Servers[/bold cyan]")
        console.print("Enter IP addresses one per line. Enter a blank line when done.")
        
        custom_dns = []
        while True:
            ip = input("DNS IP (blank to finish): ").strip()
            if not ip:
                break
                
            if self.is_valid_ip(ip):
                custom_dns.append(ip)
                console.print(f"[green]Added {ip}")
            else:
                console.print(f"[red]Invalid IP address: {ip}")
        
        if custom_dns:
            self.dns_servers["Custom"] = custom_dns
            return True
        return False

    def run(self):
        """Main execution flow of the DNS benchmark tool"""
        console.print("[bold cyan]DNS Benchmark Tool[/bold cyan]")
        console.print("This tool will compare your current DNS with popular providers.")

        # Allow user to add custom DNS (already present)
        add_custom = input("Do you want to add custom DNS to test? (y/n): ").strip().lower()
        if add_custom == 'y':
            self.add_custom_dns()

        console.print("\n[bold cyan]Select the DNS providers to test[/bold cyan]")
        available_providers = list(self.dns_servers.keys())
        for i, provider in enumerate(available_providers, 1):
            console.print(f"{i}. {provider}")
        selected = input("Enter the numbers of the providers to test, separated by commas (press Enter to test all): ").strip()

        if selected:
            try:
                # Convert choices to indices (0-based)
                selected_indices = [int(x.strip()) - 1 for x in selected.split(',')]
                # Filter only selected providers
                self.dns_servers = {available_providers[i]: self.dns_servers[available_providers[i]] 
                                    for i in selected_indices if 0 <= i < len(available_providers)}
            except Exception as e:
                console.print(f"[red]Error processing your selection: {e}. All providers will be tested.[/red]")
        
        console.print("\n[bold cyan]Starting benchmark...[/bold cyan]")
        if self.run_benchmark():
            stats = self.analyze_results()
            self.display_results(stats)
            
            # Viewing graphs
            create_chart = input("Generate the response time chart? (y/n): ").strip().lower()
            if create_chart == 'y':
                self.plot_response_times()
            
            create_map = input("Generate the traceroute map? (y/n): ").strip().lower()
            if create_map == 'y':
                self.create_traceroute_map()
            
            console.print("\n[bold green]Benchmark completed![/bold green]")
            console.print("The data can help you decide if you should change your DNS provider.")

if __name__ == "__main__":
    try:
        benchmark = DNSBenchmark()
        benchmark.run()
    except KeyboardInterrupt:
        console.print("\n[yellow]Benchmark interrupted by user")
    except Exception as e:
        console.print(f"[red]Error: {e}")