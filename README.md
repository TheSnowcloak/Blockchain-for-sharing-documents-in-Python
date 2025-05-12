# README

## This project was created as part of a diploma thesis on the topic: USABILITY OF BLOCKCHAIN TECHNOLOGY IN INDUSTRY

This repository provides a simple demonstration of a blockchain-based file sharing and transaction system. It consists of two main components:

1. **A blockchain node (server)** implemented in `blockchain.py` (using Flask).
2. **A client-side application** in `blockchain_client.py` (also using Flask).

The aim is to showcase:
- Storing and sharing files via a blockchain structure.
- Digital signing of transactions using RSA.
- Optional encryption of sensitive files (AES GCM) before uploading to the blockchain.

## Repository Structure / Files

- **`blockchain.py`**  
  This is the primary blockchain node implementation. It includes:
  - A list of transactions and blocks persisted in `blockchain_data.json`.
  - Handling of uploaded files in a `pending_uploads` folder, later moved into `uploads` upon mining a new block.
  - A simple consensus mechanism (via `resolve_conflicts`) and file synchronization between nodes.
  - By default, it runs on port **5000** and provides multiple endpoints (e.g., `/chain`, `/transactions/new`, `/node/upload`, etc.).

- **`node_index.html`, `configure.html`, and other HTML files** (those not marked as client)  
  - Provide a basic user interface to the node itself (viewing pending transactions, manually mining a block, configuring connected nodes, etc.).

- **`blockchain_client.py`**  
  - A client application that:
    - Can generate new RSA key pairs (public and private).
    - Lets you upload files (possibly encrypting them first) to the blockchain node.
    - Allows you to view transactions in the chain.
  - Make sure to change the **`NODE_URL`** variable to match your actual node address (for example, `http://YOUR_NODE_IP:5000`).

- **Client-side templates**: (`client_index.html`, `upload_file.html`, `view_transactions.html`)  
  - These define the UI for the client application (RSA key generation, file uploading, viewing transactions).

- **`uploads/`**  
  - A folder where finalized files are stored after being mined into the blockchain.

- **`pending_uploads/`**  
  - A folder for newly submitted files waiting for a block to be mined. Once a new block is created, files are moved from this folder to `uploads/`.

- **`blockchain_data.json`**  
  - A local JSON file storing the chain of blocks, nodes in the network, and any pending transactions.

## Important Steps / Notes

1. **Modifying IP/Port for the Client**   
   - In `blockchain_client.py`, the variable `NODE_URL` must be set to the address of your blockchain node (e.g., `http://192.168.1.10:5000` or `http://YOUR_PUBLIC_IP:5000`).
   - In `view_transactions.html` you will need to also find a line with `const nodeUrl = "http://127.0.0.1:5000/";`.
   In this line, you can edit the node's IP address to which it will connect.
2. **Starting the Node (server)**  
   - Run `python blockchain.py` (or `python3 blockchain.py` depending on your environment).
   - By default, it listens on `http://0.0.0.0:5000`.
   - You can then open `http://localhost:5000` in your browser to see the node’s minimal dashboard.

3. **Starting the Client**  
   - Run `python blockchain_client.py`.
   - By default, it listens on `http://0.0.0.0:8081`.
   - Open `http://localhost:8081` in your browser to access the client UI (key generation, file uploads, transaction viewing, etc.).

4. **Installing Python**  
   - If Python is not installed, visit [python.org](https://www.python.org/downloads/) to download and install a recent version (3.9+ recommended).
   - Verify your installation by running:
     ```sh
     python --version
     ```

5. **Installing Dependencies**  
   - If a `requirements.txt` file is provided, simply run:
     ```sh
     pip install -r requirements.txt
     ```
   - Otherwise, install the essential packages manually:
     ```sh
     pip install flask requests pycryptodome flask-cors
     ```
   - These packages are needed for both the node and the client.

6. **Additional Recommendations**  
   - Use HTTPS and restricted access for production, as this demonstration does not include security measures.
   - This is an **example** project illustrating blockchain fundamentals with file sharing, digital signatures, and optional encryption. Further work may be required to make it production-ready.

7. **How to open crypted files (sensitive files)**
     - In the browser (or via Postman/cURL) enter the address of node (`http://IP:PORT/decrypt/TX_ID`) where is generated `keys_db.json` file.
     -  The node should return `Content-Disposition: attachment; filename="decrypted_NameOfFile.pdf"` (or image, etc.).
     - The browser usually asks `"Do you want to save the file?"` and names it `decrypted_<OriginalName>`.
     - After downloading, you should be able to open this file (already decrypted).


