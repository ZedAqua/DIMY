# **DIMY: A Privacy-Preserving Contact Tracing Protocol**

## **Project Overview**

DIMY is a privacy-preserving digital contact tracing protocol designed to ensure data security through advanced cryptographic techniques. It supports generating ephemeral IDs (EphIDs), secret sharing and broadcasting, Bloom filter management, and key exchange. The project also includes attack node simulations to validate the security of the protocol.

---

## **Directory Structure**

- **`Dimy.py`**: Core implementation of the DIMY node, including EphID generation, secret sharing and broadcasting, data reception, and Bloom filter management.
- **`DimyServer.py`**: Server-side implementation of the DIMY protocol, responsible for processing and merging Bloom filter data received from nodes.
- **`attacker.py`**: Defines an attack node capable of simulating flood attacks and false-positive attacks.
- **`utils.py`**: Provides utility functions such as EphID generation, Shamir secret sharing, secret reconstruction, and cryptographic operations.

---

## **Key Features**

1. **Ephemeral ID (EphID) Generation**

   - Generates 32-byte random EphIDs.
   - EphIDs are split into shares for broadcasting and reconstruction.

2. **Secret Sharing and Reception**

   - Nodes broadcast shares via UDP.
   - Nodes receive shares from other nodes and reconstruct EphIDs when enough shares are collected.

3. **Bloom Filter Management**

   - Each node maintains multiple Bloom filters to store shared secrets (EncIDs).
   - Periodically merges and sends Bloom filters to the server.

4. **Attack Node Simulation**

   - Simulates flood attacks: rapidly broadcasts fake EphID shares.
   - Simulates false-positive attacks: sends forged Bloom filters to the server.

5. **Server-Side Bloom Filter Processing**
   - Matches query Bloom filters (QBF) from nodes against the contact Bloom filter (CBF).
   - Merges legitimate or fake Bloom filters from nodes.

---

## **Usage Guide**

### **1. Requirements**

- Python 3.7 or higher
- Required dependencies:
  ```bash
  pip install pybloom-live secretsharing
  ```

### **2. Running a DIMY Node**

1. Start the server (ensure the port is available):

   ```bash
   python DimyServer.py
   ```

   Expected output:

   ```
   Waiting for connection, server running on 127.0.0.1:55000
   ```

2. Start a DIMY node:
   ```bash
   python Dimy.py
   ```
   Node functionality includes:
   - Generating EphIDs and broadcasting their shares.
   - Receiving shares from other nodes and attempting reconstruction.
   - Encoding shared secrets (EncIDs) into Bloom filters and sending them to the server.

### **3. Simulating an Attack Node**

Run the attacker script:

```bash
python attacker.py
```

Attack behaviors:

- Flood Attack: Rapidly broadcasts fake EphID shares.
- False-Positive Attack: Sends forged Bloom filters to the server to cause false detections.

### **4. Key Utility Functions**

- **Generate EphID**: `generate_ephid()`
- **Secret Sharing and Reconstruction**: `generate_shares()`, `reconstruct_secret()`
- **Bloom Filter Operations**: Use `BloomFilter`'s `add()` and `union()` methods.

---

## **Highlights**

1. **Privacy Preservation**: Shamir secret sharing and Diffie-Hellman key exchange ensure robust data protection.
2. **Attack Simulation**: Attack nodes validate the protocol’s security under adverse conditions.
3. **Efficient Storage**: Bloom filters reduce storage and communication overhead.

---

## **Example Outputs**

1. **Node Generates EphID and Broadcasts Shares:**
   ```
   [TASK1]Generated ephid: <ephid_hex>
   [TASK2]Broadcasted share: <share>
   ```
2. **Reconstructing EphID After Receiving Shares:**
   ```
   [TASK4-A]Received shares more than k, try to reconstruct.
   [TASK4-B]Hash match, reconstruction successful!
   ```
3. **Attacker Switching Modes:**
   ```
   Attacker switched to fake positive attack mode
   ```

---

## **Developer**

- Project Author: ZedAqua
- GitHub Repository: [Repository Link]

---

Feel free to reach out for further support or contributions!
