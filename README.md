# README

> This work was created during the diploma thesis "USABILITY OF BLOCKCHAIN TECHNOLOGY IN INDUSTRY" at the University of West Bohemia.

## English Version

### Project Overview
This repository contains a demonstrative blockchain network for sharing documents and registering transactions. It is organised into two primary applications:

1. **Blockchain node (server)** in `blockchain_node/blockchain.py` built with Flask.
2. **Client application** in `Blockchain_client/blockchain_client.py`, also implemented with Flask.

The project demonstrates:
- Storing and sharing files through a blockchain structure.
- Digitally signing transactions with RSA.
- Optional AES-GCM encryption of sensitive files prior to uploading them to the blockchain.

### Repository Structure
- **`blockchain_node/blockchain.py`** – core node implementation keeping the chain, handling pending uploads, resolving conflicts, and exposing REST endpoints such as `/chain`, `/transactions/new`, `/node/upload`, `/nodes/register`, and many others. The node stores data in `blockchain_node/blockchain_data.json` and persists uploaded files under `blockchain_node/uploads/`.
- **`blockchain_node/templates/`** – HTML templates (e.g., `node_index.html`, `configure.html`) powering the minimal node dashboard.
- **`Blockchain_client/blockchain_client.py`** – client web app for generating RSA keys, encrypting files, and submitting transactions to a node. Update `NODE_URL` inside this file to point to the node you want to reach.
- **Client templates** – files such as `client_index.html`, `upload_file.html`, and `view_transactions.html` that define the user interface for the client.
- **`uploads/` and `pending_uploads/` directories** – temporary and final storage for files that are mined into the blockchain.
- **`requirements.txt`** – Python dependencies for both the node and the client.

### Setup and Basic Usage
1. **Install Python** – Download and install Python 3.9 or newer from [python.org](https://www.python.org/downloads/). Confirm the installation:
   ```sh
   python --version
   ```
   On Linux you may need to use `python3` instead of `python`.

2. **Install dependencies** – From the project root run:
   ```sh
   pip install -r requirements.txt
   ```
   If you prefer to install packages manually, use:
   ```sh
   pip install flask requests pycryptodome flask-cors
   ```

3. **Start the node (server)** – Navigate to the node directory and run the Flask app:
   ```sh
   cd blockchain_node
   python blockchain.py
   ```
   By default the node listens on `http://0.0.0.0:5000`. Visit `http://localhost:5000` in a browser to access the dashboard.

4. **Start the client** – Launch the client from its directory:
   ```sh
   cd Blockchain_client
   python blockchain_client.py
   ```
   The client listens on `http://0.0.0.0:8081`; open `http://localhost:8081` in your browser to generate keys, upload files, or browse transactions.

5. **Adjust node addresses in the client** – In `Blockchain_client/blockchain_client.py` update the `NODE_URL` constant to match the node’s address (for example `http://192.168.1.10:5000`). Also update `const nodeUrl = "http://127.0.0.1:5000/";` inside `Blockchain_client/templates/view_transactions.html` so the JavaScript code targets the correct node.

6. **Open encrypted files** – To download a decrypted version of a sensitive file, request the `/decrypt/<TX_ID>` endpoint (using a browser, Postman, or curl). The node responds with a `Content-Disposition: attachment` header and the decrypted file name (`decrypted_<OriginalName>`), which your browser will offer to save.

### Node Management
After at least one node is running (see **Start the node** above), use the following endpoints to manage a cluster. Each example shows both Linux/macOS syntax (`curl`) and Windows syntax (`curl.exe` in Command Prompt or PowerShell). Windows 10+ bundles `curl.exe`; for older versions install curl from [curl.se](https://curl.se/windows/) or use PowerShell’s `Invoke-RestMethod` as an alternative.

#### Register regular nodes (`/nodes/register`)
1. Prepare a list of peer addresses in `http://host:port` format.
2. Send the registration request:
   ```sh
   # Linux/macOS
   curl -X POST http://127.0.0.1:5000/nodes/register \
     -H "Content-Type: application/json" \
     -d '{"nodes": ["http://192.168.1.21:5000", "http://localhost:5001"]}'
   ```
   ```bat
   :: Windows CMD or PowerShell (single line prevents escaping issues)
   curl.exe -X POST "http://127.0.0.1:5000/nodes/register" -H "Content-Type: application/json" -d "{\"nodes\": [\"http://192.168.1.21:5000\", \"http://localhost:5001\"]}"
   ```
   > **PowerShell tip:** If `curl` maps to `Invoke-WebRequest`, call the executable explicitly via `& curl.exe ...`. Alternatively you can run:
   > ```powershell
   > Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:5000/nodes/register" -ContentType "application/json" -Body (@{ nodes = @("http://192.168.1.21:5000", "http://localhost:5001") } | ConvertTo-Json)
   > ```
3. Inspect the response to confirm the new node appears under `total_nodes`.

#### Remove nodes and verify state
- Remove a node:
  ```sh
  # Linux/macOS
  curl -X POST http://127.0.0.1:5000/nodes/remove \
    -H "Content-Type: application/json" \
    -d '{"node": "http://127.0.0.1:5001"}'
  ```
  ```bat
  :: Windows CMD or PowerShell
  curl.exe -X POST "http://127.0.0.1:5000/nodes/remove" -H "Content-Type: application/json" -d "{\"node\": \"http://127.0.0.1:5001\"}"
  ```
- Retrieve the current node list:
  ```sh
  curl http://127.0.0.1:5000/nodes/get
  ```
  ```bat
  curl.exe http://127.0.0.1:5000/nodes/get
  ```
- Trigger conflict resolution and verify the response. If you see `"Chain replaced"`, the node adopted a longer or more authoritative chain:
  ```sh
  curl http://127.0.0.1:5000/nodes/resolve
  ```
  ```bat
  curl.exe http://127.0.0.1:5000/nodes/resolve
  ```

#### Trusted nodes (`/trusted_nodes/...`)
Trusted nodes can access sensitive data and participate in Proof-of-Authority (PoA) consensus.

> **Mining access control:** Manual mining via the `/mine` endpoint is restricted to trusted nodes (or localhost). Remote, untrusted callers receive `403 Forbidden`. Ensure the machine or IP that initiates mining appears in the trusted node list before invoking the endpoint.

1. Register a trusted node:
   ```sh
   curl -X POST http://127.0.0.1:5000/trusted_nodes/register \
     -H "Content-Type: application/json" \
     -d '{"nodes": ["http://127.0.0.1:5001"]}'
   ```
   ```bat
   :: Windows CMD or PowerShell
   curl.exe -X POST "http://127.0.0.1:5000/trusted_nodes/register" -H "Content-Type: application/json" -d "{\"nodes\": [\"http://127.0.0.1:5001\"]}"
   ```
   ```bat
   :: Windows alternative without JSON escaping (URL-encoded form data)
   curl.exe -X POST "http://127.0.0.1:5000/trusted_nodes/register" --data-urlencode "nodes=http://127.0.0.1:5001"
   ```
2. Remove a trusted node:
   ```sh
   curl -X POST http://127.0.0.1:5000/trusted_nodes/remove \
     -H "Content-Type: application/json" \
     -d '{"node": "http://127.0.0.1:5001"}'
   ```
   ```bat
   :: Windows CMD or PowerShell
   curl.exe -X POST "http://127.0.0.1:5000/trusted_nodes/remove" -H "Content-Type: application/json" -d "{\"node\": \"http://127.0.0.1:5001\"}"
   ```
3. Check the trusted list:
   ```sh
   curl http://127.0.0.1:5000/trusted_nodes/get
   ```
   ```bat
   curl.exe http://127.0.0.1:5000/trusted_nodes/get
   ```

> After every change ensure each node’s `/nodes/get` and `/trusted_nodes/get` responses match so the configuration remains consistent across the network.

#### Upload files securely (`/node/upload`)
- The node now validates the HTTP `Host` header for every upload. Requests are rejected with **HTTP 400** if the host does not resolve to the current node (for example if a client spoofs another peer’s address).
- Configure the node’s own address through `/validator/configure` (`netloc` field) or by setting `LOCAL_NODE_NETLOCS` (comma-, space-, or JSON-separated list) before starting the server.
- Clients must submit uploads using the same host/port combination that peers use to reach the node so that the resulting transactions advertise a reachable file owner.

### Customising the Network and Testing Multiple Nodes
#### Change the node IP/port
1. **Edit the Flask configuration** – In `blockchain_node/blockchain.py` modify the line `app.run(host="0.0.0.0", port=5000)` to the desired port (e.g., `port=5001`) and restart the node.
2. **Use `flask run` without code changes** – Alternatively, override the port via environment variables:
   ```sh
   cd blockchain_node
   export FLASK_APP=blockchain.py
   export FLASK_RUN_PORT=5001
   flask run --host=0.0.0.0
   ```
   ```bat
   :: Windows PowerShell
   Set-Location blockchain_node
   $env:FLASK_APP = "blockchain.py"
   $env:FLASK_RUN_PORT = "5001"
   flask run --host=0.0.0.0
   ```
3. Update all clients (see **Adjust node addresses in the client**) and re-register peers with `/nodes/register` so that every instance knows the new address.

#### Add more nodes to the network
1. Start additional node instances on unique ports (e.g., 5000, 5001). Consider giving each instance its own copy of `blockchain_node` so they do not share `blockchain_data.json` or the `uploads/` directories.
2. Use `/nodes/register` and `/trusted_nodes/register` on every node to announce all peers.
3. Run one client per node or reuse a single client by switching `NODE_URL` between instances.
4. For a two-node test on the same machine open two terminals:
   - Terminal A: `python blockchain_node/blockchain.py` (port 5000).
   - Terminal B: edit the port (see above) and launch a second copy on port 5001.
   Register nodes with each other and call `/nodes/resolve` on both sides to confirm synchronisation.

### Proof-of-Authority (PoA)
1. **Configure a validator** – Provide the validator identity, private key, and advertised network location:
   ```sh
   curl -X POST http://127.0.0.1:5000/validator/configure \
     -H "Content-Type: application/json" \
     -d '{"validator_id": "validator-1", "private_key_hex": "<hex_private_key>", "netloc": "127.0.0.1:5000"}'
   ```
   Retrieve the configuration (without private key) via:
   ```sh
   curl http://127.0.0.1:5000/validator/configure
   ```
2. **Promote a regular node to trusted** – After configuring validator identity, add the node to the trusted set (`/trusted_nodes/register`). Only trusted validators can sign blocks.
3. **Rotate public keys** – Distribute an updated public key:
   ```sh
   curl -X POST http://127.0.0.1:5000/trusted_nodes/keys/rotate \
     -H "Content-Type: application/json" \
     -d '{"validator_id": "validator-1", "public_key_hex": "<hex_public_key>", "netloc": "127.0.0.1:5000"}'
   ```
   Other trusted nodes can review the registry through:
   ```sh
   curl http://127.0.0.1:5000/trusted_nodes/keys
   ```
4. **Set the quorum threshold** – Define how many validator signatures must approve a block:
   ```sh
   curl -X POST http://127.0.0.1:5000/consensus/quorum \
     -H "Content-Type: application/json" \
     -d '{"threshold": 2}'
   ```
   Check the current threshold:
   ```sh
   curl http://127.0.0.1:5000/consensus/quorum
   ```
5. **Approve blocks** – A trusted validator can submit a signature for a block (replace `5` with the target block index):
   ```sh
   curl -X POST http://127.0.0.1:5000/blocks/5/approve \
     -H "Content-Type: application/json" \
     -d '{"validator_id": "validator-2", "signature": "<hex_signature>"}'
   ```
   The signature is verified against the stored public key and block data.

---

## Czech Version (Česká verze)

### Přehled projektu
Tento repozitář obsahuje demonstrační blockchainovou síť pro sdílení dokumentů a registraci transakcí. Organizace projektu zahrnuje dvě hlavní aplikace:

1. **Blockchainový uzel (server)** v `blockchain_node/blockchain.py`, postavený na Flasku.
2. **Klientská aplikace** v `Blockchain_client/blockchain_client.py`, taktéž ve Flasku.

Projekt demonstruje:
- Ukládání a sdílení souborů pomocí blockchainové struktury.
- Digitální podepisování transakcí pomocí RSA.
- Volitelné šifrování citlivých souborů algoritmem AES-GCM před nahráním na blockchain.

### Struktura repozitáře
- **`blockchain_node/blockchain.py`** – základní implementace uzlu spravující řetězec, čekající nahrávky, řešení konfliktů a REST rozhraní jako `/chain`, `/transactions/new`, `/node/upload`, `/nodes/register` atd. Uzel ukládá data do `blockchain_node/blockchain_data.json` a soubory do `blockchain_node/uploads/`.
- **`blockchain_node/templates/`** – HTML šablony (například `node_index.html`, `configure.html`) pro jednoduché rozhraní uzlu.
- **`Blockchain_client/blockchain_client.py`** – klientská webová aplikace pro generování RSA klíčů, šifrování souborů a odesílání transakcí na uzel. Aktualizujte konstantu `NODE_URL`, aby ukazovala na požadovaný uzel.
- **Klientské šablony** – soubory jako `client_index.html`, `upload_file.html` a `view_transactions.html`, které definují uživatelské rozhraní klienta.
- **Adresáře `uploads/` a `pending_uploads/`** – dočasné a finální úložiště souborů, které byly vytěženy do blockchainu.
- **`requirements.txt`** – Python závislosti pro uzel i klienta.

### Nastavení a základní použití
1. **Instalace Pythonu** – Stáhněte a nainstalujte Python 3.9 nebo novější z [python.org](https://www.python.org/downloads/). Instalaci ověříte příkazem:
   ```sh
   python --version
   ```
   V Linuxu může být potřeba použít `python3` místo `python`.

2. **Instalace závislostí** – V kořenovém adresáři projektu spusťte:
   ```sh
   pip install -r requirements.txt
   ```
   Pokud chcete balíčky nainstalovat ručně, použijte:
   ```sh
   pip install flask requests pycryptodome flask-cors
   ```

3. **Spuštění uzlu (serveru)** – Přejděte do adresáře uzlu a spusťte Flask aplikaci:
   ```sh
   cd blockchain_node
   python blockchain.py
   ```
   Ve výchozím nastavení uzel naslouchá na `http://0.0.0.0:5000`. Otevřete `http://localhost:5000` v prohlížeči a zobrazte nástěnku.

4. **Spuštění klienta** – Spusťte klienta z jeho adresáře:
   ```sh
   cd Blockchain_client
   python blockchain_client.py
   ```
   Klient naslouchá na `http://0.0.0.0:8081`; otevřete `http://localhost:8081` v prohlížeči, abyste generovali klíče, nahrávali soubory nebo prohlíželi transakce.

5. **Úprava adres uzlů v klientovi** – V `Blockchain_client/blockchain_client.py` upravte konstantu `NODE_URL`, aby odpovídala adrese uzlu (například `http://192.168.1.10:5000`). Změňte také `const nodeUrl = "http://127.0.0.1:5000/";` v `Blockchain_client/templates/view_transactions.html`, aby JavaScript cílil na správný uzel.

6. **Otevírání šifrovaných souborů** – Chcete-li stáhnout dešifrovanou verzi citlivého souboru, zavolejte endpoint `/decrypt/<TX_ID>` (prohlížečem, Postmanem nebo pomocí curl). Uzel odpoví hlavičkou `Content-Disposition: attachment` a názvem `decrypted_<OriginalName>`, soubor si pak můžete uložit.

### Správa uzlů
Jakmile máte spuštěný alespoň jeden uzel (viz **Spuštění uzlu**), můžete cluster spravovat pomocí následujících endpointů. Příklady obsahují syntax pro Linux/macOS (`curl`) i pro Windows (`curl.exe` v Příkazovém řádku nebo PowerShellu). Windows 10 a novější obsahují `curl.exe`; ve starších verzích jej nainstalujte z [curl.se](https://curl.se/windows/) nebo použijte PowerShell `Invoke-RestMethod`.

#### Registrace běžných uzlů (`/nodes/register`)
1. Připravte seznam adres ve formátu `http://host:port`.
2. Odeslání registračního požadavku:
   ```sh
   # Linux/macOS
   curl -X POST http://127.0.0.1:5000/nodes/register \
     -H "Content-Type: application/json" \
     -d '{"nodes": ["http://192.168.1.21:5000", "http://localhost:5001"]}'
   ```
   ```bat
   :: Windows CMD nebo PowerShell (jednořádkový příkaz eliminuje chyby s escapováním)
   curl.exe -X POST "http://127.0.0.1:5000/nodes/register" -H "Content-Type: application/json" -d "{\"nodes\": [\"http://192.168.1.21:5000\", \"http://localhost:5001\"]}"
   ```
   > **Tip pro PowerShell:** Pokud `curl` odkazuje na `Invoke-WebRequest`, spusťte přímo spustitelný soubor pomocí `& curl.exe ...`. Alternativně můžete využít:
   > ```powershell
   > Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:5000/nodes/register" -ContentType "application/json" -Body (@{ nodes = @("http://192.168.1.21:5000", "http://localhost:5001") } | ConvertTo-Json)
   > ```
3. V odpovědi zkontrolujte, že se nový uzel objevil pod klíčem `total_nodes`.

#### Odstranění uzlů a ověření stavu
- Odstranění uzlu:
  ```sh
  # Linux/macOS
  curl -X POST http://127.0.0.1:5000/nodes/remove \
    -H "Content-Type: application/json" \
    -d '{"node": "http://127.0.0.1:5001"}'
  ```
  ```bat
  :: Windows CMD nebo PowerShell
  curl.exe -X POST "http://127.0.0.1:5000/nodes/remove" -H "Content-Type: application/json" -d "{\"node\": \"http://127.0.0.1:5001\"}"
  ```
- Získání aktuálního seznamu uzlů:
  ```sh
  curl http://127.0.0.1:5000/nodes/get
  ```
  ```bat
  curl.exe http://127.0.0.1:5000/nodes/get
  ```
- Spuštění řešení konfliktů a kontrola odpovědi. Pokud obsahuje `"Chain replaced"`, uzel převzal delší nebo autoritativnější řetězec:
  ```sh
  curl http://127.0.0.1:5000/nodes/resolve
  ```
  ```bat
  curl.exe http://127.0.0.1:5000/nodes/resolve
  ```

#### Trusted uzly (`/trusted_nodes/...`)
Trusted uzly mají přístup k citlivým datům a podílejí se na konsenzu Proof-of-Authority.

1. Registrace trusted uzlu:
   ```sh
   curl -X POST http://127.0.0.1:5000/trusted_nodes/register \
     -H "Content-Type: application/json" \
     -d '{"nodes": ["http://127.0.0.1:5001"]}'
   ```
   ```bat
   :: Windows CMD nebo PowerShell
   curl.exe -X POST "http://127.0.0.1:5000/trusted_nodes/register" -H "Content-Type: application/json" -d "{\"nodes\": [\"http://127.0.0.1:5001\"]}"
   ```
2. Odebrání trusted uzlu:
   ```sh
   curl -X POST http://127.0.0.1:5000/trusted_nodes/remove \
     -H "Content-Type: application/json" \
     -d '{"node": "http://127.0.0.1:5001"}'
   ```
   ```bat
   :: Windows CMD nebo PowerShell
   curl.exe -X POST "http://127.0.0.1:5000/trusted_nodes/remove" -H "Content-Type: application/json" -d "{\"node\": \"http://127.0.0.1:5001\"}"
   ```
3. Kontrola trusted seznamu:
   ```sh
   curl http://127.0.0.1:5000/trusted_nodes/get
   ```
   ```bat
   curl.exe http://127.0.0.1:5000/trusted_nodes/get
   ```

> Po každé změně zkontrolujte odpovědi `/nodes/get` a `/trusted_nodes/get` na všech uzlech, aby konfigurace zůstala konzistentní.

### Přizpůsobení sítě a testování více uzlů
#### Změna IP/portu uzlu
1. **Úprava konfigurace Flasku** – V `blockchain_node/blockchain.py` změňte řádek `app.run(host="0.0.0.0", port=5000)` na požadovaný port (např. `port=5001`) a uzel restartujte.
2. **Použití `flask run` bez změn kódu** – Alternativně nastavte port pomocí proměnných prostředí:
   ```sh
   cd blockchain_node
   export FLASK_APP=blockchain.py
   export FLASK_RUN_PORT=5001
   flask run --host=0.0.0.0
   ```
   ```bat
   :: Windows PowerShell
   Set-Location blockchain_node
   $env:FLASK_APP = "blockchain.py"
   $env:FLASK_RUN_PORT = "5001"
   flask run --host=0.0.0.0
   ```
3. Aktualizujte všechny klienty (viz **Úprava adres uzlů v klientovi**) a znovu zaregistrujte protějšky pomocí `/nodes/register`, aby každý uzel znal novou adresu.

#### Přidání více uzlů do sítě
1. Spusťte další instance uzlu na unikátních portech (např. 5000, 5001). Každé instanci dejte vlastní kopii adresáře `blockchain_node`, aby nesdílely `blockchain_data.json` a adresáře `uploads/`.
2. Na každém uzlu oznamte všechny protějšky pomocí `/nodes/register` a podle potřeby `/trusted_nodes/register`.
3. Spusťte jednoho klienta pro každý uzel nebo používejte jediného klienta a přepínejte `NODE_URL`.
4. Pro test dvou uzlů na jednom počítači otevřete dva terminály:
   - Terminál A: `python blockchain_node/blockchain.py` (port 5000).
   - Terminál B: upravte port (viz výše) a spusťte druhou kopii na portu 5001.
   Uzel vzájemně zaregistrujte a na obou spusťte `/nodes/resolve`, abyste ověřili synchronizaci.

### Proof-of-Authority (PoA)
1. **Konfigurace validátora** – Zadejte identitu validátora, privátní klíč a inzerovanou síťovou adresu:
   ```sh
   curl -X POST http://127.0.0.1:5000/validator/configure \
     -H "Content-Type: application/json" \
     -d '{"validator_id": "validator-1", "private_key_hex": "<hex_private_key>", "netloc": "127.0.0.1:5000"}'
   ```
   Konfiguraci (bez privátního klíče) zobrazíte pomocí:
   ```sh
   curl http://127.0.0.1:5000/validator/configure
   ```
2. **Povýšení běžného uzlu na trusted** – Po konfiguraci identity přidejte uzel do seznamu trusted (`/trusted_nodes/register`). Jen trusted validátoři mohou podepisovat bloky.
3. **Rotace veřejných klíčů** – Distribuujte aktualizovaný veřejný klíč:
   ```sh
   curl -X POST http://127.0.0.1:5000/trusted_nodes/keys/rotate \
     -H "Content-Type: application/json" \
     -d '{"validator_id": "validator-1", "public_key_hex": "<hex_public_key>", "netloc": "127.0.0.1:5000"}'
   ```
   Ostatní trusted uzly si mohou registr klíčů prohlédnout přes:
   ```sh
   curl http://127.0.0.1:5000/trusted_nodes/keys
   ```
4. **Nastavení quorum** – Určete, kolik podpisů je potřeba pro schválení bloku:
   ```sh
   curl -X POST http://127.0.0.1:5000/consensus/quorum \
     -H "Content-Type: application/json" \
     -d '{"threshold": 2}'
   ```
   Aktuální práh zjistíte:
   ```sh
   curl http://127.0.0.1:5000/consensus/quorum
   ```
5. **Schvalování bloků** – Trusted validátor může přidat podpis k bloku (nahraďte `5` cílovým indexem bloku):
   ```sh
   curl -X POST http://127.0.0.1:5000/blocks/5/approve \
     -H "Content-Type: application/json" \
     -d '{"validator_id": "validator-2", "signature": "<hex_signature>"}'
   ```
   Podpis je ověřen proti uloženému veřejnému klíči a datům bloku.
