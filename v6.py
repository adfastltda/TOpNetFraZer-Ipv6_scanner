import multithreading
import websocket
import argparse
import sys
import subprocess
import socket
import ssl
import ipaddress
import logging
import shlex
import socket
import dns.resolver  # Importa a biblioteca dnspython

# Configurar o logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class BugScanner(multithreading.MultiThreadRequest):
    def convert_host_port(self, host, port):
        """Format IPv6 address properly for URLs."""
        return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"

    def get_url(self, host, port, uri=None):
        """Generate a valid URL for the scanner."""
        port = str(port)
        protocol = 'https' if port == '443' else 'http'
        return f'{protocol}://{self.convert_host_port(host, port)}' + (f'/{uri}' if uri is not None else '')

    def resolve_hostname(self, host):
        """Resolve hostname to IPv6 address."""
        try:
            answers = dns.resolver.resolve(host, 'AAAA')
            for rdata in answers:
                return str(rdata)
        except dns.resolver.NXDOMAIN:
            logging.warning(f"Hostname {host} not found.")
            return None
        except dns.resolver.NoAnswer:
            logging.warning(f"No AAAA records found for {host}.")
            return None
        except Exception as e:
            logging.error(f"Error resolving hostname {host}: {e}")
            return None

class DirectScanner(BugScanner):
    def task(self, payload):
        """Performs HTTP scanning."""
        method = payload['method']
        host = payload['host']
        port = payload['port']

        try:
            response = self.request(method, self.get_url(host, port), retry=1, timeout=3, allow_redirects=False)
        except Exception as e:
            logging.error(f"Error during HTTP request to {host}:{port} - {e}")
            return  # Ignore failures

        if response:
            self.task_success(payload)
            logging.info(f"HTTP {method} request successful on {host}:{port} - Status: {response.status_code}")

class ProxyScanner(DirectScanner):
    proxy = []

    def request(self, *args, **kwargs):
        """Use a proxy for requests."""
        proxy_url = self.get_url(self.proxy[0], self.proxy[1])
        proxies = {'http': proxy_url, 'https': proxy_url}
        try:
            return super().request(*args, proxies=proxies, **kwargs)
        except Exception as e:
            logging.error(f"Error using proxy {proxy_url}: {e}")
            return None

class SSLScanner(BugScanner):
    def task(self, payload):
        """Perform an SSL handshake to check if SSL is enabled."""
        host = payload['host']

        try:
            sock = socket.create_connection((host, 443), timeout=5, family=socket.AF_INET6)
            context = ssl.create_default_context()
            ssl_sock = context.wrap_socket(sock, server_hostname=host)  # Wrap o socket normal em SSL
            ssl_sock.do_handshake() # Inicia o handshake SSL/TLS
            self.task_success(payload)
            logging.info(f"SSL handshake successful on {host}:443")
        except socket.timeout:
            logging.warning(f"Timeout connecting to {host}:443")
        except socket.gaierror as e:
            logging.error(f"Error resolving hostname {host}: {e}")
        except ssl.SSLError as e:
            logging.debug(f"SSL error on {host}:443 - {e}")
        except Exception as e:
            logging.error(f"Unexpected error on {host}:443 - {e}", exc_info=True)
        finally:
            if 'ssl_sock' in locals() and ssl_sock: # Verifica se o socket SSL foi criado e existe
                ssl_sock.close() # Encerra a conexão SSL
            elif 'sock' in locals() and sock:
                sock.close() # Se não, fecha o socket comum

class PingScanner(BugScanner):
    def ping_host(self, host):
        """Ping an IPv6 host."""
        param = '-n' if subprocess.os.name == 'nt' else '-c'
        ping_cmd = 'ping6' if subprocess.os.name != 'nt' else 'ping -6'
        command = [ping_cmd, param, '1', host]

        try:
            # Usar shlex.quote para escapar os argumentos do comando
            command = [shlex.quote(arg) for arg in command]
            command_str = ' '.join(command)

            result = subprocess.run(command_str, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            if result.returncode == 0:
                return True
            else:
                logging.debug(f"Ping failed for {host}: {result.stderr}")
                return False
        except FileNotFoundError:
            logging.error("Ping command not found. Ensure 'ping6' (or 'ping -6' on Windows) is installed and in your PATH.")
            return False
        except Exception as e:
            logging.error(f"Error executing ping command for {host}: {e}")
            return False

    def task(self, payload):
        """Execute a ping task."""
        host = payload['host']
        if self.ping_host(host):
            self.task_success(payload)
            logging.info(f"Ping successful for {host}")
        else:
             logging.debug(f"Ping failed for {host}")

class UdpScanner(BugScanner):
    def scan_udp_port(self, host, port):
        """Check if a UDP port is open on an IPv6 host."""
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock.settimeout(1)
            sock.sendto(b'', (host, int(port)))
            try:
                sock.recvfrom(1024)
                logging.info(f"UDP port {port} is open or unfiltered on {host}")  # Melhoria no log
                return True
            except socket.timeout:
                 logging.debug(f"UDP port {port} timed out on {host}")
                return False  # Timeout, pode estar filtrado ou não ter resposta
            except socket.error as e:
                logging.debug(f"UDP port {port} error on {host}: {e}")
                return False  # Erro, provavelmente fechado
        except socket.gaierror as e:  # Trata erros de resolução de nome
             logging.error(f"Error resolving hostname {host}: {e}")
            return False
        except Exception as e:
            logging.error(f"Error scanning UDP port {port} on {host}: {e}")
            return False
        finally:
            sock.close()

    def task(self, payload):
        """Run UDP scan on IPv6 host."""
        host = payload['host']
        port = payload['port']
        if self.scan_udp_port(host, port):
            self.task_success(payload)

class WebSocketScanner(BugScanner):
    def task(self, payload):
        """Check if WebSocket is open on an IPv6 host."""
        host = payload['host']
        port = payload['port']  # Assume a porta padrão 80 se não especificada

        try:
            url = f"ws://[{host}]:{port}"  # Garante formatação correta para IPv6
            ws = websocket.create_connection(url, timeout=5)  # Aumentar o timeout
            ws.send("ping")
            result = ws.recv() # Recebe a resposta
            self.task_success(payload)
            logging.info(f"WebSocket connection successful on {host}:{port} - Received: {result}")
            ws.close()
        except websocket.WebSocketException as e:
            logging.debug(f"WebSocket connection failed on {host}:{port} - {e}")
        except socket.timeout:
            logging.debug(f"WebSocket connection timed out on {host}:{port}")
        except Exception as e:
            logging.error(f"Error during WebSocket connection to {host}:{port} - {e}")

def get_arguments():
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--filename', type=str, help='Filename containing hosts')
    parser.add_argument('-c', '--cdir', type=str, help='IPv6 CIDR (e.g., 2001:db8::/64)')
    parser.add_argument('-m', '--mode', choices=('direct', 'proxy', 'ssl', 'udp', 'ws', 'ping'), default='direct', type=str, help='Scan mode')
    parser.add_argument('-M', '--method', default='head', type=str, help='HTTP method')
    parser.add_argument('-p', '--port', default='80', type=str, help='Port(s)')
    parser.add_argument('-P', '--proxy', default='', type=str, help='Proxy (host:port)')
    parser.add_argument('-T', '--threads', type=int, help='Number of threads')
    parser.add_argument('-o', '--output', type=str, help='Output file')
    return parser.parse_args(), parser

def generate_ips_from_cidr(cidr):
    """Generate IPv6 addresses from a CIDR block."""
    ip_list = []
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        for ip in network.hosts():
            ip_list.append(str(ip))
    except ValueError as e:
        logging.error(f"Invalid CIDR: {e}")
    return ip_list

def main():
    """Main function to initialize the scanner."""
    arguments, parser = get_arguments()

    if not arguments.filename and not arguments.cdir:
        parser.print_help()
        sys.exit(1)

    method_list = arguments.method.split(',')
    host_list = []

    if arguments.filename:
        try:
            with open(arguments.filename, 'r') as file:
                hosts = file.read().splitlines()
                for host in hosts:
                    if ':' not in host and '.' in host: # Parece ser um nome de domínio
                        ipv6_address = BugScanner().resolve_hostname(host)
                        if ipv6_address:
                            host_list.append(ipv6_address)
                        else:
                            logging.warning(f"Could not resolve or ignoring hostname: {host}") # Usa o logger
                    else:
                        host_list.append(host)
        except FileNotFoundError:
            logging.error(f"File not found: {arguments.filename}")
            sys.exit(1)
        except Exception as e:
            logging.error(f"Error reading file {arguments.filename}: {e}")
            sys.exit(1)

    elif arguments.cdir:
        host_list = generate_ips_from_cidr(arguments.cdir)

    port_list = [int(p) for p in arguments.port.split(',')] # Converte para inteiros
    proxy = arguments.proxy.split(':')

    # Select scanner mode
    if arguments.mode == 'direct':
        scanner = DirectScanner()
    elif arguments.mode == 'ssl':
        scanner = SSLScanner()
    elif arguments.mode == 'ping':
        scanner = PingScanner()
    elif arguments.mode == 'ws':
        scanner = WebSocketScanner()
    elif arguments.mode == 'proxy':
        if len(proxy) != 2:
            logging.error('--proxy requires host:port') # Use logging
            sys.exit(1)
        scanner = ProxyScanner()
        scanner.proxy = proxy
    elif arguments.mode == 'udp':
        scanner = UdpScanner()
    else:
        logging.error('Mode not available!')
        sys.exit(1)

    # Configure scanner
    scanner.method_list = method_list
    scanner.host_list = host_list
    scanner.port_list = port_list
    scanner.threads = arguments.threads
    scanner.start()

    # Save results if needed
    if arguments.output:
        try:
            with open(arguments.output, 'w') as file:
                for result in scanner.success_list():
                    file.write(str(result) + '\n')
            logging.info(f"Results saved to {arguments.output}")
        except Exception as e:
            logging.error(f"Error writing to output file {arguments.output}: {e}")

if __name__ == '__main__':
    main()
