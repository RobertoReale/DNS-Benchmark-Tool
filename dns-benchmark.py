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
import re
import threading
from collections import defaultdict
from typing import Dict, List, Optional, Any, Union

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
    # os.execv is unreliable on Windows; spawn a new process and exit cleanly instead
    result = subprocess.call([sys.executable] + sys.argv)
    sys.exit(result)

# Initialize console for rich output
console = Console()

# Global rate limiter: max 1 ipinfo.io request every 0.3s across all threads
_geo_lock = threading.Lock()
_geo_last_call: float = 0.0

class DNSBenchmark:
    def __init__(self) -> None:
        self.config_file: str = "dns_benchmark_config.json"
        self.dns_servers: Dict[str, List[str]] = {}
        self.test_domains: List[str] = []
        
        # Load configuration or defaults
        self.load_config()
        
        # Get the system's default DNS
        self.get_system_dns()
        
        # Initialize results containers
        self.results: Dict[str, Dict[str, Any]] = {}
        self.trace_results: Dict[str, Dict[str, Any]] = {}
        self.locations: Dict[str, Dict[str, Any]] = {}
        self.my_location: Optional[Dict[str, Any]] = None

    def load_config(self) -> None:
        """Load configuration from JSON or use defaults"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    self.dns_servers = config.get("dns_servers", {})
                    self.test_domains = config.get("test_domains", [])
                    if self.dns_servers and self.test_domains:
                        console.print(f"[green]Configuration loaded from {self.config_file}")
                        return
            except Exception as e:
                console.print(f"[yellow]Warning: Could not load config file: {e}. Using defaults.")

        # Default fallback values
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
        
        self.test_domains = [
            "google.com", "facebook.com", "amazon.com", "netflix.com",
            "microsoft.com", "apple.com", "cloudflare.com", "akamai.com",
            "fastly.com", "cdn.jsdelivr.net"
        ]
        
        # Create default config file for future customization
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump({
                    "dns_servers": {k: v for k, v in self.dns_servers.items() if k != "System Default"},
                    "test_domains": self.test_domains
                }, f, indent=4)
        except Exception:
            pass

    def get_system_dns(self) -> None:
        """Detect system's default DNS servers"""
        if "System Default" not in self.dns_servers:
            self.dns_servers["System Default"] = []
            
        try:
            if platform.system() != "Windows":
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        if line.startswith('nameserver'):
                            self.dns_servers["System Default"].append(line.split()[1])
            else:
                output = subprocess.check_output(
                    ["powershell", "-Command", 
                     "Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses"], 
                    text=True
                )
                for ip in output.strip().split('\n'):
                    if ip.strip() and self.is_valid_ip(ip.strip()):
                        self.dns_servers["System Default"].append(ip.strip())
                        
            if not self.dns_servers["System Default"]:
                resolver = dns.resolver.Resolver()
                self.dns_servers["System Default"] = list(resolver.nameservers)
                
            console.print(f"[green]System default DNS servers: {', '.join(self.dns_servers['System Default'])}")
            
        except Exception as e:
            console.print(f"[yellow]Warning: Could not detect system DNS servers: {e}")
            console.print("[yellow]Using localhost as fallback")
            self.dns_servers["System Default"] = ["127.0.0.1"]

    def is_valid_ip(self, ip: str) -> bool:
        """Check if a string is a valid IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def get_my_location(self) -> bool:
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
                console.print(f"[yellow]Warning: Could not determine your location. HTTP status: {response.status_code}")
        except Exception as e:
            console.print(f"[yellow]Warning: Could not determine your location: {e}")
        
        self.my_location = {
            "ip": "Unknown", "city": "Unknown", "region": "Unknown",
            "country": "Unknown", "loc": "0,0"
        }
        return False

    def is_private_ip(self, ip: str) -> bool:
        """Check if an IP address is private"""
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def get_dns_server_location(self, ip: str) -> Dict[str, Any]:
        """Get the geographic location of a DNS server with global rate limiting"""
        if ip in self.locations:
            return self.locations[ip]

        global _geo_last_call
        with _geo_lock:
            now = time.time()
            wait = 0.3 - (now - _geo_last_call)
            if wait > 0:
                time.sleep(wait)
            _geo_last_call = time.time()

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
            elif response.status_code == 429:
                console.print(f"[yellow]Warning: Rate limited by ipinfo.io for IP {ip}, skipping.")
        except Exception as e:
            console.print(f"[yellow]Warning: Geo lookup failed for {ip}: {e}")

        default_location = {
            "ip": ip, "hostname": "Unknown", "city": "Unknown",
            "region": "Unknown", "country": "Unknown", "org": "Unknown", "loc": "0,0"
        }
        self.locations[ip] = default_location
        return default_location

    def query_dns(self, dns_server: str, domain: str, query_type: str = 'A') -> Dict[str, Any]:
        """Query a DNS server for a specific domain and record type"""
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]
        resolver.timeout = 2
        resolver.lifetime = 4
        
        try:
            start_time = time.time()
            answers = resolver.resolve(domain, query_type)
            end_time = time.time()
            
            response_time = (end_time - start_time) * 1000
            records = [answer.to_text() for answer in answers]
            
            return {"status": "success", "response_time": response_time, "records": records}
        except dns.resolver.NXDOMAIN:
            return {"status": "nxdomain", "response_time": 0, "records": []}
        except dns.resolver.NoAnswer:
            return {"status": "noanswer", "response_time": 0, "records": []}
        except dns.resolver.Timeout:
            return {"status": "timeout", "response_time": 0, "records": []}
        except Exception as e:
            return {"status": "error", "response_time": 0, "records": [], "error": str(e)}

    def trace_route(self, target_ip: str) -> List[Dict[str, Any]]:
        """Perform a traceroute to the DNS server with robust Regex parsing"""
        hops: List[Dict[str, Any]] = []
        
        if platform.system() == "Windows":
            cmd = ["tracert", "-d", "-h", "30", target_ip]
        else:
            cmd = ["traceroute", "-n", "-m", "30", target_ip]
        
        try:
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            
            line_count = 0
            if process.stdout:
                for line in process.stdout:
                    line_count += 1
                    if line_count <= 2 and ("traceroute to" in line.lower() or "tracing route" in line.lower()):
                        continue
                    
                    hop_num: Optional[int] = None
                    hop_ip: Optional[str] = None
                    response_time: Optional[float] = None
                    
                    ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                    if ip_match:
                        hop_ip = ip_match.group(0)
                        if hop_ip == target_ip and line_count <= 2: 
                            continue
                    else:
                        continue
                        
                    hop_match = re.match(r'\s*(\d+)', line)
                    if hop_match:
                        hop_num = int(hop_match.group(1))
                        
                    time_match = re.search(r'([<]?[\d.,]+)\s*ms', line)
                    if time_match:
                        try:
                            response_time = float(time_match.group(1).replace('<', '').replace(',', '.'))
                        except ValueError:
                            pass
                    
                    if hop_num is not None and hop_ip is not None and hop_ip != "*":
                        if not any(h['hop'] == hop_num for h in hops):
                            hops.append({"hop": hop_num, "ip": hop_ip, "time": response_time})
            
            process.wait(timeout=60)

            # Lookup hop locations in parallel to avoid sequential 0.3s sleeps
            def lookup_hop(hop: Dict[str, Any]) -> None:
                if self.is_valid_ip(hop["ip"]) and not self.is_private_ip(hop["ip"]):
                    hop["location"] = self.get_dns_server_location(hop["ip"])

            with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(hops) or 1)) as hop_pool:
                concurrent.futures.wait([hop_pool.submit(lookup_hop, h) for h in hops])

            return hops
            
        except subprocess.TimeoutExpired:
            process.kill()
            console.print(f"[yellow]Warning: Traceroute to {target_ip} timed out")
            return []
        except Exception as e:
            console.print(f"[yellow]Warning: Traceroute to {target_ip} failed: {e}")
            return []

    def benchmark_dns_server(self, dns_provider: str, dns_server: str) -> Dict[str, Any]:
        """Benchmark a single DNS server against all test domains"""
        results: Dict[str, Any] = {
            "provider": dns_provider,
            "server": dns_server,
            "queries": {}
        }
        
        for domain in self.test_domains:
            for record_type in ['A', 'AAAA', 'MX']:
                query_times = []
                records = []
                last_error_status = "success"

                for _ in range(3):
                    query_result = self.query_dns(dns_server, domain, record_type)
                    if query_result["status"] == "success":
                        query_times.append(query_result["response_time"])
                        if not records and query_result["records"]:
                            records = query_result["records"]
                    else:
                        last_error_status = query_result["status"]

                status = "success" if query_times else last_error_status
                
                if query_times:
                    avg_time = statistics.mean(query_times)
                    min_time = min(query_times)
                    max_time = max(query_times)
                    std_dev = statistics.stdev(query_times) if len(query_times) > 1 else 0
                else:
                    avg_time = min_time = max_time = std_dev = 0
                
                key = f"{domain}/{record_type}"
                results["queries"][key] = {
                    "status": status, "avg_time": avg_time, "min_time": min_time,
                    "max_time": max_time, "std_dev": std_dev, "records": records
                }
        
        results["location"] = self.get_dns_server_location(dns_server)
        return results

    def run_benchmark(self, custom_dns: Optional[Union[str, List[str]]] = None) -> bool:
        """Run the benchmark against all DNS servers using Multi-threading"""
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
                console.print("[red]Error: Custom DNS must be an IP address or a list")
                return False
        
        self.get_my_location()
        
        for provider in self.dns_servers.keys():
            self.results[provider] = {}
            self.trace_results[provider] = {}

        tasks: List[tuple] = []
        for provider, servers in self.dns_servers.items():
            for server in servers:
                tasks.append((provider, server))
                
        total_servers = len(tasks)
        total_steps = total_servers * (1 + len(self.test_domains) * 3)
        
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn()
        ) as progress:
            main_task = progress.add_task("[cyan]Running DNS benchmarks concurrently...", total=total_steps)
            
            def worker(provider: str, server: str) -> None:
                result = self.benchmark_dns_server(provider, server)
                self.results[provider][server] = result
                progress.advance(main_task, len(self.test_domains) * 3)
                
                trace = self.trace_route(server)
                self.trace_results[provider][server] = trace
                progress.advance(main_task, 1)

            max_threads = min(20, len(tasks) if tasks else 1)
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = [executor.submit(worker, p, s) for p, s in tasks]
                concurrent.futures.wait(futures)
                
        return True

    def analyze_results(self) -> Dict[str, Any]:
        """Analyze the benchmark results"""
        stats: Dict[str, Any] = {}
        
        for provider, servers in self.results.items():
            provider_times = []
            provider_success = 0
            provider_total = 0

            stats[provider] = {"servers": {}}

            for server, result in servers.items():
                server_times = []
                server_success = 0
                server_total = 0

                for _, query_result in result["queries"].items():
                    if query_result["status"] == "success":
                        server_times.append(query_result["avg_time"])
                        server_success += 1
                        provider_times.append(query_result["avg_time"])
                        provider_success += 1

                    server_total += 1
                    provider_total += 1

                if server_times:
                    avg_time = statistics.mean(server_times)
                    min_time = min(server_times)
                    max_time = max(server_times)
                    reliability = (server_success / server_total) * 100
                else:
                    avg_time = min_time = max_time = reliability = 0

                stats[provider]["servers"][server] = {
                    "avg_time": avg_time, "min_time": min_time, "max_time": max_time,
                    "reliability": reliability, "success": server_success, "total": server_total
                }
            
            if provider_times:
                avg_time = statistics.mean(provider_times)
                min_time = min(provider_times)
                max_time = max(provider_times)
                reliability = (provider_success / provider_total) * 100
            else:
                avg_time = min_time = max_time = reliability = 0
            
            stats[provider].update({
                "avg_time": avg_time, "min_time": min_time, "max_time": max_time,
                "reliability": reliability, "success": provider_success, "total": provider_total
            })
        
        return stats

    def display_results(self, stats: Dict[str, Any]) -> None:
        """Display benchmark results in a tabular format"""
        provider_table = Table(title="DNS Provider Performance Summary")
        provider_table.add_column("Provider", style="cyan")
        provider_table.add_column("Avg Response (ms)", justify="right")
        provider_table.add_column("Min (ms)", justify="right")
        provider_table.add_column("Max (ms)", justify="right")
        provider_table.add_column("Reliability (%)", justify="right")
        provider_table.add_column("Location", style="green")
        
        sorted_providers = sorted(stats.keys(), key=lambda p: stats[p]["avg_time"] if stats[p]["avg_time"] > 0 else float('inf'))
        
        for provider in sorted_providers:
            provider_stats = stats[provider]
            location_info = "Unknown"
            for server in self.results[provider]:
                if "location" in self.results[provider][server]:
                    loc = self.results[provider][server]["location"]
                    location_info = f"{loc.get('city', 'Unknown')}, {loc.get('country', 'Unknown')}"
                    break
            
            provider_table.add_row(
                provider, f"{provider_stats['avg_time']:.2f}", f"{provider_stats['min_time']:.2f}",
                f"{provider_stats['max_time']:.2f}", f"{provider_stats['reliability']:.1f}", location_info
            )
        
        console.print(provider_table)
        
        server_table = Table(title="DNS Server Performance Details")
        server_table.add_column("Provider", style="cyan")
        server_table.add_column("Server IP", style="blue")
        server_table.add_column("Avg Response (ms)", justify="right")
        server_table.add_column("Reliability (%)", justify="right")
        server_table.add_column("Hops", justify="right")
        server_table.add_column("Location", style="green")
        
        for provider in sorted_providers:
            provider_stats = stats[provider]
            sorted_servers = sorted(
                provider_stats["servers"].keys(), 
                key=lambda s: provider_stats["servers"][s]["avg_time"] if provider_stats["servers"][s]["avg_time"] > 0 else float('inf')
            )
            
            for server in sorted_servers:
                server_stats = provider_stats["servers"][server]
                hop_count = "N/A"
                if provider in self.trace_results and server in self.trace_results[provider]:
                    hop_count = str(len(self.trace_results[provider][server]))
                
                location_info = "Unknown"
                if "location" in self.results[provider][server]:
                    loc = self.results[provider][server]["location"]
                    location_info = f"{loc.get('city', 'Unknown')}, {loc.get('country', 'Unknown')}"
                
                server_table.add_row(
                    provider, server, f"{server_stats['avg_time']:.2f}",
                    f"{server_stats['reliability']:.1f}", hop_count, location_info
                )
        
        console.print(server_table)
        self.display_recommendation(stats, sorted_providers)
    
    def display_recommendation(self, stats: Dict[str, Any], sorted_providers: List[str]) -> None:
        """Display a recommendation based on the benchmark results"""
        best_provider = None
        best_score = float('inf')

        # Normalize avg_time to 0-1 so speed and reliability are comparable
        all_times = [stats[p]["avg_time"] for p in sorted_providers if stats[p]["avg_time"] > 0]
        max_time = max(all_times) if all_times else 1.0

        for provider in sorted_providers:
            provider_stats = stats[provider]
            if provider_stats["avg_time"] > 0:
                norm_time = provider_stats["avg_time"] / max_time
                norm_unreliability = 1.0 - (provider_stats["reliability"] / 100.0)
                score = norm_time * 0.7 + norm_unreliability * 0.3
                if score < best_score:
                    best_score = score
                    best_provider = provider
        
        console.print("\n[bold green]Recommendation:[/bold green]")
        
        if best_provider and best_provider != "System Default":
            system_stats = stats.get("System Default", {"avg_time": 0, "reliability": 0})
            if system_stats["avg_time"] > 0:
                speed_diff = ((system_stats["avg_time"] - stats[best_provider]["avg_time"]) / system_stats["avg_time"]) * 100
                if speed_diff > 10:
                    console.print(f"[green]Switching to {best_provider} could improve your DNS resolution speed by approximately {speed_diff:.1f}%.")
                else:
                    console.print(f"[yellow]Your current DNS performs well. Switching to {best_provider} would only provide a minor improvement of {speed_diff:.1f}%.")
            else:
                console.print(f"[green]The {best_provider} DNS provider showed the best overall performance in our tests.")
                
            if best_provider in self.dns_servers:
                server_ips = ", ".join(self.dns_servers[best_provider])
                console.print(f"[green]To use {best_provider}, configure your DNS servers to: {server_ips}")
        else:
            console.print("[yellow]Your current system DNS servers are already performing optimally.")

    def plot_response_times(self) -> None:
        """Create a bar chart of average response times"""
        providers = []
        avg_times = []
        
        for provider, servers in self.results.items():
            all_times = []
            for server, result in servers.items():
                for query, query_result in result["queries"].items():
                    if query_result["status"] == "success":
                        all_times.append(query_result["avg_time"])
            
            if all_times:
                providers.append(provider)
                avg_times.append(statistics.mean(all_times))
        
        if not providers:
            return
            
        sorted_data = sorted(zip(providers, avg_times), key=lambda x: x[1])
        providers = [x[0] for x in sorted_data]
        avg_times = [x[1] for x in sorted_data]
        
        plt.figure(figsize=(10, 6))
        bars = plt.bar(providers, avg_times, color='skyblue')
        
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height + 1,
                    f'{height:.1f} ms', ha='center', va='bottom', rotation=0)
        
        plt.title('Average DNS Response Time by Provider')
        plt.xlabel('DNS Provider')
        plt.ylabel('Average Response Time (ms)')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"dns_benchmark_response_times_{timestamp}.png"
        plt.savefig(filename)
        console.print(f"[green]Response time chart saved as: {filename}")
        plt.show()
        plt.close()

    def create_traceroute_map(self) -> None:
        """Create an interactive map showing the traceroute paths"""
        if not self.my_location:
            console.print("[yellow]Warning: Could not create traceroute map - location data unavailable")
            return
        
        user_lat, user_lon = self.my_location["loc"].split(",")
        m = folium.Map(location=[float(user_lat), float(user_lon)], zoom_start=4)
        
        folium.Marker(
            [float(user_lat), float(user_lon)],
            popup=f"Your Location: {self.my_location['city']}, {self.my_location['country']}",
            icon=folium.Icon(color='green', icon='home')
        ).add_to(m)
        
        providers = list(self.dns_servers.keys())
        colors = cm.rainbow(np.linspace(0, 1, len(providers)))
        provider_colors = {provider: f'#{int(r*255):02x}{int(g*255):02x}{int(b*255):02x}' 
                          for provider, (r, g, b, _) in zip(providers, colors)}
        
        dns_markers = set()
        
        for provider, servers in self.dns_servers.items():
            color = provider_colors.get(provider, '#3388ff')
            
            for server in servers:
                if server in self.trace_results.get(provider, {}):
                    hops = self.trace_results[provider][server]
                    server_location = None
                    if provider in self.results and server in self.results[provider]:
                        if "location" in self.results[provider][server]:
                            server_location = self.results[provider][server]["location"]
                    
                    if not server_location or "," not in server_location.get("loc", ""):
                        continue
                    
                    server_lat, server_lon = server_location["loc"].split(",")
                    
                    if self.is_private_ip(server):
                        marker_position = [float(user_lat) + 0.1, float(user_lon) + 0.1]
                        marker_key = f"private-{server}"
                        
                        if marker_key not in dns_markers:
                            dns_markers.add(marker_key)
                            folium.Marker(
                                marker_position,
                                popup=f"{provider} DNS: {server}<br>Network: Local Network",
                                icon=folium.Icon(color='blue', icon='wifi')
                            ).add_to(m)
                    else:
                        marker_key = f"{server_lat},{server_lon},{server}"
                        if marker_key not in dns_markers:
                            dns_markers.add(marker_key)
                            folium.Marker(
                                [float(server_lat), float(server_lon)],
                                popup=f"{provider} DNS: {server}<br>Location: {server_location['city']}, {server_location['country']}",
                                icon=folium.Icon(color='red', icon='server')
                            ).add_to(m)
                    
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
                                
                            folium.PolyLine(
                                [(last_lat, last_lon), (hop_lat, hop_lon)],
                                color=color, weight=2, opacity=0.7,
                                tooltip=f"Hop {hop['hop']}: {hop['ip']} ({hop['location'].get('city','Unknown')})"
                            ).add_to(m)
                            last_lat, last_lon = hop_lat, hop_lon
                    
                    if server_location and "loc" in server_location:
                        try:
                            server_lat = float(server_lat)
                            server_lon = float(server_lon)
                        except ValueError:
                            continue  # skip to next server in the outer for-server loop
                        
                        if not self.is_private_ip(server) and not (server_lat == 0.0 and server_lon == 0.0):
                            folium.PolyLine(
                                [(float(user_lat), float(user_lon)), (server_lat, server_lon)],
                                color=color, weight=1, opacity=0.4, dash_array='5,5',
                                tooltip=f"Direct path to {provider} ({server})"
                            ).add_to(m)

        legend_html = '''
        <div style="position: fixed; bottom: 50px; left: 50px; width: 200px; height: auto;
                    border:2px solid grey; z-index:9999; font-size:14px;
                    background-color:white; padding: 10px; border-radius: 5px;">
        <p><b>DNS Providers</b></p>
        '''
        for provider, color in provider_colors.items():
            legend_html += f'<p><span style="background-color:{color};display:inline-block;width:10px;height:10px;margin-right:5px;"></span>{provider}</p>'
        
        legend_html += '''
        <p><span style="color:green;font-size:18px;">&#8962;</span> Your Location</p>
        <p><span style="color:red;font-size:18px;">&#9783;</span> DNS Servers</p>
        <p><span style="color:blue;font-size:18px;">&#8776;</span> Local Network DNS</p>
        <p><hr style="margin:5px 0;"></p>
        <p style="font-size:12px;"><i>Solid lines: Actual path<br>Dotted lines: Direct path</i></p>
        </div>
        '''
        m.get_root().html.add_child(folium.Element(legend_html))
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"dns_traceroute_map_{timestamp}.html"
        m.save(filename)
        console.print(f"[green]Traceroute map saved as: {filename}")
        
        try:
            if platform.system() == 'Darwin':
                subprocess.call(['open', filename])
            elif platform.system() == 'Windows':
                os.startfile(filename)
            else:
                subprocess.call(['xdg-open', filename])
        except Exception as e:
            console.print(f"[yellow]Info: Could not automatically open the map: {e}")

    def add_custom_dns(self) -> bool:
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

    def run(self) -> None:
        """Main execution flow of the DNS benchmark tool"""
        console.print("[bold cyan]DNS Benchmark Tool[/bold cyan]")
        console.print("This tool will compare your current DNS with popular providers.")

        add_custom = input("Do you want to add custom DNS to test? (y/n): ").strip().lower()
        if add_custom == 'y':
            self.add_custom_dns()

        console.print("\n[bold cyan]Select the DNS providers to test[/bold cyan]")
        available_providers = list(self.dns_servers.keys())
        for i, provider in enumerate(available_providers, 1):
            console.print(f"{i}. {provider}")
        selected = input("Enter numbers separated by commas (press Enter to test all): ").strip()

        if selected:
            try:
                selected_indices = [int(x.strip()) - 1 for x in selected.split(',')]
                self.dns_servers = {available_providers[i]: self.dns_servers[available_providers[i]] 
                                    for i in selected_indices if 0 <= i < len(available_providers)}
            except Exception as e:
                console.print(f"[red]Error processing selection: {e}. All will be tested.[/red]")
        
        console.print("\n[bold cyan]Starting benchmark...[/bold cyan]")
        if self.run_benchmark():
            stats = self.analyze_results()
            self.display_results(stats)
            
            create_chart = input("Generate the response time chart? (y/n): ").strip().lower()
            if create_chart == 'y':
                self.plot_response_times()
            
            create_map = input("Generate the traceroute map? (y/n): ").strip().lower()
            if create_map == 'y':
                self.create_traceroute_map()
            
            console.print("\n[bold green]Benchmark completed![/bold green]")

if __name__ == "__main__":
    try:
        benchmark = DNSBenchmark()
        benchmark.run()
    except KeyboardInterrupt:
        console.print("\n[yellow]Benchmark interrupted by user")
    except Exception as e:
        console.print(f"[red]Error: {e}")