import time
import random
import socket
from utils import *
import threading
from pybloom_live import BloomFilter
import pickle


class DIMYNode:
    def __init__(self, p, g):
        self.ephid = None
        self.shares = []
        self.ephid_hash = None
        self.private_key, self.public_key = generate_dh_keypair(p, g)
        self.other_public_key = None
        self.shared_secret = None
        self.broadcast_ip = '255.255.255.255'
        self.port = 50000
        self.received_shares = []
        self.bloom_filters = [BloomFilter(capacity=1000, error_rate=0.001)]
        self.lock = threading.Lock()
        self.is_positive = False
        self.ephid_hash_index = random.randint(1, 1000000)
        self.received_data = {}
        self.share_timeout = 60  # Timeout in seconds for shares
        
    def ephid_generate(self):
        self.ephid = generate_ephid()
        self.shares = generate_shares(5, 3, self.ephid)
        self.ephid_hash = hash_ephid(self.ephid)
        print(f"[TASK1]Generated ephid: {self.ephid.hex()}")
        self.ephid_hash_index = random.randint(1, 1000000)
        

    def broadcast_shares(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        while True:
            self.ephid_generate()
            for share in self.shares:
                if random.uniform(0, 1) < 0.5:
                    print(f"[TASK3-A]Message dropped: {share[0]}-{share[1]}")
                    time.sleep(3)
                    continue
                with self.lock:
                    message = f"{self.ephid_hash},{share[0]},{share[1]},{self.public_key},{self.ephid_hash_index}"
                    sock.sendto(message.encode(), (self.broadcast_ip, self.port))
                    print(f"[TASK2]Broadcasted share: {share[0]},{share[1]}")
                time.sleep(3)

    def receive_shares(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', self.port))

        while True:
            try:
                data, _ = sock.recvfrom(1024)
                parts = data.decode().split(',')
                if len(parts) < 5:
                    continue

                received_hash = parts[0]
                received_hash_index = int(parts[4])
                if received_hash == self.ephid_hash:
                    continue

                share = (int(parts[1]), parts[2])
                other_public_key = int(parts[3])
                print(f"[TASK3-B]Received share: {share}")

                if received_hash_index not in self.received_data:
                    self.received_data[received_hash_index] = {
                        'hash': received_hash,
                        'shares': [],
                        'other_public_key': other_public_key,
                        'last_received': time.time()
                    }

                self.received_data[received_hash_index]['shares'].append(share)
                self.received_data[received_hash_index]['last_received'] = time.time()
                if len(self.received_data[received_hash_index]['shares']) == 3:
                    print('[TASK4-A]Received shares more than k, try to reconstruct.')
                    try:
                        reconstructed_ephid = reconstruct_secret(self.received_data[received_hash_index]['shares'])
                        reconstructed_hash = hash_ephid(reconstructed_ephid)
                        reconstructed_hash_index = received_hash_index

                        if reconstructed_hash == self.received_data[reconstructed_hash_index]['hash']:
                            print("[TASK4-B]Hash match, reconstruction successful!")
                            self.shared_secret = compute_shared_secret(self.private_key, self.received_data[received_hash_index]['other_public_key'], p)
                            print(f'[TASK5-A]Compute shared secret')
                            print(f"[TASK5-B]Shared key (EncID): {self.shared_secret}")

                            with self.lock:
                                self.bloom_filters[-1].add(self.shared_secret)
                                print(f"[TASK7-A]EncID add to the Bloom filter,Current Bloom filter state: {self.bloom_filters[-1].__str__()}")
                            print(f"[TASK6]Shared key encoded in Bloom filter: {self.shared_secret},and delete it ")
                            self.shared_secret = None
                            break
                        else:
                            print("Hash mismatch, reconstruction failed!")

                    except Exception as e:
                        print(f"Reconstruction failed: {e}")

            except Exception as e:
                print(f"Error processing received data: {e}")

    def manage_bloom_filters(self):
        while True:
            time.sleep(30)    # Start a new Bloom filter every 30 seconds (for testing)
            with self.lock:
                # Start a new Bloom filter
                self.bloom_filters.append(BloomFilter(capacity=1000, error_rate=0.001))
                print(f"[TASK7-B]Started a new Bloom filter every 90 seconds, now there are {len(self.bloom_filters)} Bloom filters")
                # Remove Bloom filters older than 9 minutes
                if len(self.bloom_filters) > 6:
                    self.bloom_filters.pop(0)
                    print(f"[TASK7-B]Removed a Bloom filter older than 9 minutes, now there are {len(self.bloom_filters)} Bloom filters")
   
    def merge_and_send_filters(self):
        while True:
            time.sleep(180)  # Merge Bloom filters every 180 seconds (for testing)
            with self.lock:
                if not self.is_positive:
                    if random.uniform(0,1) < 0.4:
                        self.is_positive = True
                        print('Node turned positive')
                
                if self.is_positive:
                    cbf = BloomFilter(capacity=1000, error_rate=0.001)
                    for bf in self.bloom_filters:
                        cbf = cbf.union(bf)
                    
                    print(f"[TASK9]Generated contact Bloom filter (CBF)")
                    self.send_filter_to_server(cbf, "CBF")
                else:
                    qbf = BloomFilter(capacity=1000, error_rate=0.001)
                    for bf in self.bloom_filters:
                        qbf = qbf.union(bf)
                    
                    print(f"[TASK8]Generated query Bloom filter (QBF)")
                    self.send_filter_to_server(qbf, "QBF")

    def send_filter_to_server(self, bf, filter_type):
        try:
            # Serialize Bloom filter object to a byte string using pickle
            serialized_bf = pickle.dumps(bf)
            message = f"{filter_type}:".encode() + serialized_bf
            self.tcp_socket.sendall(message)
            response = self.tcp_socket.recv(4096).decode()
            print(f"[TASK10-B]Server response: {response}")
        except Exception as e:
            print(f"Failed to send {filter_type} to server: {e}")

    def infection_determinated(self):
        for i in range(3):
            if self.is_positive:
                continue
            else:
                if random.uniform(0,1) < 0.1:
                    self.is_positive = True

    def connect_to_server(self):
        try:
            self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_socket.connect(('127.0.0.1', 55000))
            print("Successfully connected to server")
        except Exception as e:
            print(f"Failed to connect to server: {e}")

    def run(self):
        thread_broadcast_shares = threading.Thread(target=self.broadcast_shares)
        thread_receive_shares = threading.Thread(target=self.receive_shares)
        thread_manage_bloom_filters = threading.Thread(target=self.manage_bloom_filters)
        thread_merge_and_send_filters = threading.Thread(target=self.merge_and_send_filters)

        time.sleep(3)
        thread_broadcast_shares.start()
        thread_receive_shares.start()
        thread_manage_bloom_filters.start()
        thread_merge_and_send_filters.start()

        thread_broadcast_shares.join()
        thread_receive_shares.join()
        thread_manage_bloom_filters.join()
        thread_merge_and_send_filters.join()
    

    def discard_old_shares(self):
        while True:
            time.sleep(30)  # Check every 30 seconds
            with self.lock:
                current_time = time.time()
                keys_to_discard = []
                for index, data in self.received_data.items():
                    if len(data['shares']) < 3 and (current_time - data['last_received']) > self.share_timeout:
                        keys_to_discard.append(index)

                for key in keys_to_discard:
                    print(f"[TASK3-C]Discarding shares for EphID hash index {key} due to less than k")
                    del self.received_data[key]

if __name__ == "__main__":
    p = 23 # Example prime number
    g = 5  # Example generator
    node = DIMYNode(p, g)
    node.connect_to_server()
    node.run()
