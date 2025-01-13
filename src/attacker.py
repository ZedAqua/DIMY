from Dimy import DIMYNode
import time
import random
import socket
from utils import *
import threading
from pybloom_live import BloomFilter
import os

class AttackerNode(DIMYNode):
    def __init__(self, p, g):
        super().__init__(p, g)
        self.attack_mode = "flood"
        self.fake_ephids = []
        self.attack_switch_time = time.time() + 10  # Switch to fake positive attack after 10 seconds
        self.p = p  # Save p value
        self.g = g  # Save g value
        self.private_key, self.public_key = generate_dh_keypair(p, g)

    def ephid_generate(self):
        super().ephid_generate()
        self.fake_ephids.append(self.ephid)
        

    def generate_mismatched_shares(self):
        # Generate mismatched shares
        fake_ephid = os.urandom(32)
        fake_ephid_hash = hash_ephid(fake_ephid)
        fake_shares = generate_shares(5, 3, fake_ephid)
        return fake_ephid_hash, fake_shares

    def broadcast_shares(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        while True:
            if self.attack_mode == "flood":
                print('[TASK11-B]Start Attacking other nodes.')
                fake_ephid_hash, fake_shares = self.generate_mismatched_shares()
                for share in fake_shares:
                    message = f"{fake_ephid_hash},{share[0]},{share[1]},{self.public_key},{random.randint(1, 1000000)}"
                    sock.sendto(message.encode(), (self.broadcast_ip, self.port))
                time.sleep(0.1)  # Fast sending
            else:  # fake_positive
                self.ephid_generate()
                super().broadcast_shares()
            
            # Check if the attack mode needs to be switched
            if time.time() > self.attack_switch_time and self.attack_mode == "flood":
                self.attack_mode = "fake_positive"
                print("Attacker switched to fake positive attack mode")

    def receive_shares(self):
        # Process reception logic like a normal node to establish EncID channel
        p = self.p
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
                print(f"Received share: {share}, expected hash: {received_hash},")

                if received_hash_index not in self.received_data:
                    self.received_data[received_hash_index] = {
                        'hash': received_hash,
                        'shares': [],
                        'other_public_key': other_public_key,
                    }

                self.received_data[received_hash_index]['shares'].append(share)
                print(f"Received shares count for index {received_hash_index}: {len(self.received_data[received_hash_index]['shares'])}")
                print(self.received_data[received_hash_index]['shares'])

                if len(self.received_data[received_hash_index]['shares']) == 3:
                    try:
                        reconstructed_ephid = reconstruct_secret(self.received_data[received_hash_index]['shares'])
                        reconstructed_hash = hash_ephid(reconstructed_ephid)
                        reconstructed_hash_index = received_hash_index

                        if reconstructed_hash == self.received_data[reconstructed_hash_index]['hash']:
                            print("Hash match, reconstruction successful!")
                            self.shared_secret = compute_shared_secret(self.private_key, self.received_data[received_hash_index]['other_public_key'], self.p)
                            print(f"Shared key (EncID): {self.shared_secret}")

                            with self.lock:
                                self.bloom_filters[-1].add(self.shared_secret)
                            print(f"Shared key encoded in Bloom filter: {self.shared_secret}")
                            self.shared_secret = None
                            break
                        else:
                            print("Hash mismatch, reconstruction failed!")

                    except Exception as e:
                        print(f"Reconstruction failed: {e}")

            except Exception as e:
                print(f"Error processing received data: {e}")

    def merge_and_send_filters(self):
        while True:
            time.sleep(180)
            with self.lock:
                if self.attack_mode == "fake_positive":
                    self.is_positive = True
                cbf = BloomFilter(capacity=1000, error_rate=0.001)
                for bf in self.bloom_filters:
                    cbf = cbf.union(bf)
                
                if self.attack_mode == "fake_positive":
                    print("Attacker generated fake positive contact Bloom filter (CBF)")
                    self.send_filter_to_server(cbf, "CBF")
                else:
                    print("Attacker does not send filter in flood mode")

    def run(self):
        self.connect_to_server()
        threads = [
            threading.Thread(target=self.broadcast_shares),
            threading.Thread(target=self.receive_shares),
            threading.Thread(target=self.manage_bloom_filters),
            threading.Thread(target=self.merge_and_send_filters)
        ]
        
        for thread in threads:
            thread.start()
        
        for thread in threads:
            thread.join()

if __name__ == "__main__":
    p = 23 # Example prime number
    g = 5  # Example generator
    attacker = AttackerNode(p, g)
    attacker.run()
