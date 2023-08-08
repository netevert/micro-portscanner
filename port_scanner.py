"""
Simple concurrent port scanner module

Point it against scanme.nmap.org to test it
"""

import argparse
from socket import socket, AF_INET, SOCK_STREAM
from concurrent.futures import ThreadPoolExecutor

class PortScanner:
    """Port scanner object"""
    def __init__(self, concurrency_engine, address_family=AF_INET, socket_type=SOCK_STREAM):
        self.concurrency_engine = concurrency_engine
        self.address_family = address_family
        self.socket_type = socket_type
        
    def test_port(self, host, port):
        """Object method to test port connections for a target host.

            Returns True in case of a successfull connection.
            Otherwise false.
            """
        with socket(self.address_family, self.socket_type) as sock:
            # se a timeout of a few seconds
            sock.settimeout(3)
            # handle connection failure exceptions
            try:
                # attempt a connection
                sock.connect((host, port))
                # return true if connection is successfull
                return True
            except:
                # return false if connection is unsuccessfull
                return False
            
    def run_scan(self, host, port_range):
        """Object method to run port scan against a target host.

            Prints all ports where a successfull connection has
            been made.
            """
        # initiate concurrengy engine
        scan_engine = self.concurrency_engine(len(range(port_range)), host, range(port_range+1))
        # start scan
        scan_engine.run_tasks(self.test_port)
        


class ConcurrencyEngine:
    """Concurrency engine based on ThreadPoolExecutor to speed up port scans"""
    def __init__(self, max_threads, target_host, port_range):
        self.max_threads = max_threads
        self.target_host = target_host
        self.port_range = port_range

    def run_tasks(self, scan_task):
        """Object method to run ThreadPoolExecutor tasks"""
        # create the thread pool
        with ThreadPoolExecutor(self.max_threads) as executor:
            # dispatch tasks
            results = executor.map(scan_task, [self.target_host]*len(self.port_range), self.port_range)
            # report results in order
            for port, is_open in zip(self.port_range, results):
                if is_open:
                    print(f"{self.target_host}:{port} open")

def main():
    """Main program entry point"""
    # Set-up commandline arguments 
    parser = argparse.ArgumentParser(description="Simple port scanner")
    parser.add_argument("-t", "--target", help="Specifies the target host to scan", type=str, required= True)
    parser.add_argument("-r", "--range", help="Specifies the port range to scan", type=int, default=1024)
    args = parser.parse_args()

    # initialize scanner and concurrency engine, then run scan
    print(f"Scanning {args.target}...")
    PortScanner(ConcurrencyEngine).run_scan(args.target, args.range)

if __name__ == "__main__":
    main()
