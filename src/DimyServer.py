import socket
from pybloom_live import BloomFilter
import threading
import pickle

class DIMYReceiver:
    def __init__(self):
        self.ip = '127.0.0.1'
        self.port = 55000
        self.cbf = BloomFilter(capacity=1000, error_rate=0.001)

    def handle_client(self, client_socket):
        while True:
            try:
                data = client_socket.recv(4096)
                if not data:
                    print('Received data is empty')

                filter_type, serialized_bf = data.split(b':', 1)
                bf = pickle.loads(serialized_bf)

                if filter_type.decode() == "QBF":
                    # Check if QBF overlaps with CBF
                    print('[TASK10-A]QBF detected, performing match check')
                    intersection = bf.bitarray & self.cbf.bitarray
                    match = intersection.any()
                    response = "Positive Contact" if match else "No Contact"
                    print('[TASK10-C]response:', response)

                elif filter_type.decode() == "CBF":
                    # Merge the received CBF
                    print('CBF detected, performing merge')
                    self.cbf = self.cbf.union(bf)
                    response = "CBF Received"
                    print('TASK10-C]response:', response)

                client_socket.send(response.encode())
            except Exception as e:
                print(f"Exception occurred while handling client request: {e}")
                break

    def build_connection(self):
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.bind((self.ip, self.port))
        tcp.listen(10)
        print(f"Waiting for connection, server running on {self.ip}:{self.port}")
        while True:
            try:
                client_socket, addr = tcp.accept()
                print(f"Accepted connection from {addr}")
                # Each client connection is handled by a separate thread
                client_handler = threading.Thread(target=self.handle_client, args=(client_socket,))
                client_handler.start()
            except Exception as e:
                print(f"Exception occurred while accepting connection: {e}")

if __name__ == "__main__":
    receiver = DIMYReceiver()
    receiver.build_connection()
