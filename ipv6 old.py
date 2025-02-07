import multithreading
import websocket
import argparse
import sys
import subprocess
import socket
import ssl
import ipaddress

class BugScanner(multithreading.MultiThreadRequest):
    def request_connection_error(self, *args, **kwargs):
        return 1

    def request_read_timeout(self, *args, **kwargs):
        return 1

    def request_timeout(self, *args, **kwargs):
        return 1

    def convert_host_port(self, host, port):
        return f"[{host}]:{port}" if port not in ['80', '443'] else f"[{host}]"

    def get_url(self, host, port, uri=None):
        port = str(port)
        protocol = 'https' if port == '443' else 'http'
        return f'{protocol}://{self.convert_host_port(host, port)}' + (f'/{uri}' if uri is not None else '')

    def init(self):
        self._threads = getattr(self, '_threads', 25)
        self._threads = self.threads or self._threads

    def complete(self):
        pass

class PingScanner(BugScanner):
    def __init__(self, threads=35):
        super().__init__(threads)
        self.host_list = []

    def get_task_list(self):
        for host in self.filter_list(self.host_list):
            yield {'host': host}

    def log_info(self, status, host):
        super().log(f'\033[36m{status:<6}\033[0m  \033[92m{host}\033[0m')

    def log_info_result(self, **kwargs):
        status = kwargs.get('status', '')
        host = kwargs.get('host', '')

        if status == 'Reachable':
            self.log_info('True', host)

    def init(self):
        super().init()
        self.log_info('Stat', 'Host')
        self.log_info('----', '----')

    def ping_host(self, host):
        try:
            param = '-n' if subprocess.os.name == 'nt' else '-c'
            ping_cmd = 'ping6' if subprocess.os.name != 'nt' else 'ping -6'
            command = [ping_cmd, param, '1', host]

            response = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return response.returncode == 0
        except Exception:
            return False

    def task(self, payload):
        host = payload['host']
        self.log_replace(host)

        if self.ping_host(host):
            response = {
                'host': host,
                'status': 'Reachable'
            }
            self.task_success(host)
            self.log_info_result(**response)

class UdpScanner(BugScanner):
    def __init__(self, threads=30):
        super().__init__(threads)
        self.host_list = []
        self.port_list = []

    def get_task_list(self):
        for host in self.filter_list(self.host_list):
            for port in self.filter_list(self.port_list):
                yield {
                    'host': host,
                    'port': port
                }

    def log_info(self, status, host, port):
        super().log(f'\033[36m{status:<6}\033[0m  \033[38;5;208m{port}\033[0m  \033[92m{host}\033[0m')

    def log_info_result(self, **kwargs):
        status = kwargs.get('status', '')
        host = kwargs.get('host', '')
        port = kwargs.get('port', '')

        if status == 'Open':
            self.log_info('True', host, port)

    def init(self):
        super().init()
        self.log_info('Stat', 'Host', 'Port')
        self.log_info('----', '----', '----')

    def scan_udp_port(self, host, port):
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock.settimeout(1)
            sock.sendto(b'', (host, int(port)))
            sock.recvfrom(1024)
            return True
        except socket.timeout:
            return False
        except socket.error:
            return False
        finally:
            sock.close()

    def task(self, payload):
        host = payload['host']
        port = payload['port']
        self.log_replace(f'{host}:{port}')

        if self.scan_udp_port(host, port):
            response = {
                'host': host,
                'port': port,
                'status': 'Open'
            }
            self.task_success(f'{host}:{port}')
            self.log_info_result(**response)

def get_arguments():
    parser = argparse.ArgumentParser(formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=52))
    parser.add_argument(
        '-f', '--filename',
        help='Filename',
        type=str,
    )
    parser.add_argument(
        '-c', '--cdir',
        help='IPv6 CIDR (e.g., 2001:db8::/64)',
        type=str,
    )
    parser.add_argument(
        '-m', '--mode',
        help='mode',
        dest='mode',
        choices=('ping', 'udp'),
        type=str,
        default='ping',
    )
    parser.add_argument(
        '-p', '--port',
        help='port',
        dest='port_list',
        type=str,
        default='80',
    )
    parser.add_argument(
        '-T', '--threads',
        help='threads',
        dest='threads',
        type=int,
    )
    return parser.parse_args(), parser

def generate_ips_from_cidr(cidr):
    ip_list = []
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        for ip in network.hosts():
            ip_list.append(str(ip))
    except ValueError as e:
        print("Error:", e)
    return ip_list

def main():
    arguments, parser = get_arguments()

    if not arguments.filename and not arguments.cdir:
        parser.print_help()
        sys.exit()

    if arguments.filename:
        host_list = open(arguments.filename).read().splitlines()
    elif arguments.cdir:
        ip_list = generate_ips_from_cidr(arguments.cdir)
        host_list = [str(ip) for ip in ip_list]

    port_list = arguments.port_list.split(',')

    if arguments.mode == 'ping':
        scanner = PingScanner()
    elif arguments.mode == 'udp':
        scanner = UdpScanner()
    else:
        sys.exit('Not Available!')

    scanner.host_list = host_list
    scanner.port_list = port_list
    scanner.threads = arguments.threads
    scanner.start()

if __name__ == '__main__':
    main()
