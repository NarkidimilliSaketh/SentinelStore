# SentinelStore: An Decentralized Secure Storage System

![SentinelStore Logo]

**SentinelStore is a feature-complete proof-of-concept for a next-generation decentralized storage platform. It is built on a zero-knowledge architecture, ensuring that users have absolute privacy and control over their data. The system combines client-side cryptography, fault-tolerant sharding, and a decentralized P2P network to provide a secure, resilient, and collaborative file storage solution.**

---

## ✨ Core Features

This project successfully implements a wide range of advanced features, demonstrating a complete and robust system:

#### 🔐 Security & Privacy (Zero-Knowledge)
*   **End-to-End Encryption:** All files are encrypted and decrypted exclusively in the user's browser. The servers never see unencrypted data.
*   **Password-Protected Keys:** User's private keys are themselves encrypted with a key derived from their password, ensuring no one but the user can access their core cryptographic identity.
*   **Secure Authentication:** User sessions are managed with industry-standard JWTs, and all sensitive API endpoints are protected.
*   **Secure Deletion:** Files cannot be deleted without password confirmation, preventing accidental or malicious data loss from a compromised but active session.

#### 🌐 Decentralization & Fault Tolerance
*   **P2P Storage Network:** Encrypted file shares are stored across a multi-node, decentralized network built on a simplified Kademlia DHT model.
*   **User-Driven Fault Tolerance:** Users can select an "Importance Level" (Normal, Important, Critical) for each file, which dynamically adjusts the redundancy parameters using **Shamir's Secret Sharing**.
*   **Resilience:** The system can withstand the failure of multiple P2P nodes and still perfectly reconstruct user files.
*   **Persistence & Self-Healing:** The P2P network is persistent. Nodes store data on disk and automatically re-announce their data to the network upon restart.

#### 🤝 Collaboration & Management
*   **Secure File Sharing:** Users can securely share files with other registered users using a state-of-the-art hybrid encryption model (asymmetric keys for sharing symmetric file keys).
*   **Access Control:** File owners can view who their files are shared with and revoke access at any time.
*   **Bulk Operations:** A full suite of power-user features, including multi-file upload, download, sharing, and deletion.
*   **File Management:** Users can view file details, sort, and filter their file lists.

#### 🛡️ Administrative & Monitoring
*   **Admin Dashboard:** A separate, role-based dashboard for administrators to monitor the health and statistics of the entire platform.
*   **Real-Time Network Monitoring:** The admin panel provides a live view of the status, peer count, and storage load of each P2P node.
*   **User Management:** Admins can view and manage the user base.
*   **Network Maintenance:** Admins can trigger advanced operations like **Garbage Collection** (to purge orphaned data) and **Dynamic Re-sharding** (to upgrade the fault tolerance of a user's file).

---

## 🏛️ System Architecture

SentinelStore is built on a modern microservice architecture, orchestrated with Docker.

1.  **React Frontend (Client):** The "brain" of the system. A powerful single-page application that handles all user interaction and, most importantly, all cryptographic operations (encryption, key management, sharding).
2.  **Metadata Service (Python/FastAPI):** The central "directory". It manages user accounts, file ownership, sharing permissions, and the audit log. It communicates with the MongoDB database.
3.  **P2P Network (Python/FastAPI + Kademlia):** A federated network of independent nodes that form a simplified Distributed Hash Table (DHT). This is the "body" of the system, responsible for the physical storage and decentralized retrieval of encrypted data shares.
4.  **MongoDB Atlas (Database):** A cloud-hosted NoSQL database used for all persistent metadata.

![System Architecture Diagram]
<img width="1836" height="811" alt="image" src="https://github.com/user-attachments/assets/0897c43f-2571-4556-88a4-2879c3be8007" />

---

## 🚀 Getting Started: Installation & Running the Project

Follow these steps to get the entire SentinelStore ecosystem running on your local machine.

### Prerequisites
*   [Docker](https://www.docker.com/products/docker-desktop/) and Docker Compose
*   [Node.js](https://nodejs.org/) (v18 or newer) and npm
*   A code editor like [VS Code](https://code.visualstudio.com/)
*   A free [MongoDB Atlas](https://www.mongodb.com/cloud/atlas/register) account

### Installation Steps

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/your-username/sentinelstore.git
    cd sentinelstore
    ```

2.  **Configure Backend Services:**
    *   Navigate to the `v2/metadata_service` directory.
    *   Create a file named `.env` by copying the example: `cp .env.example .env`.
    *   Open the new `.env` file and paste your **MongoDB Atlas connection string** into the `MONGO_URL` variable.

3.  **Install Frontend Dependencies:**
    *   Navigate to the `v2/frontend` directory.
    *   Run the following command to install all the necessary packages:
    ```bash
    npm install
    ```

4.  **Build and Run the Entire System:**
    *   Navigate back to the **root directory** of the project (`sentinelstore`).
    *   Run the following Docker Compose command. This will build the Docker images for all services and start them.
    ```bash
    docker-compose up --build
    ```
    *   The first build may take several minutes as it downloads base images and installs dependencies. Subsequent builds will be much faster.

---

## 🧪 How to Test the Application

Once all services are running, you can test the full functionality.

### 1. Create Users and an Admin

1.  **Start Fresh:** For a clean test, it's best to start with an empty database. Go to your MongoDB Atlas dashboard and "Drop" the `users`, `files`, `access_control`, and `logs` collections if they exist.
2.  **Register Users:**
    *   Open your browser and go to **`http://localhost:5173`**.
    *   Register a normal user (e.g., `alice` with password `alicepass`).
    *   Register another user who will be your admin (e.g., `admin` with password `adminpass`).
3.  **Promote to Admin:**
    *   Open **MongoDB Compass** and connect to your Atlas cluster.
    *   Find the `users` collection in the `sentinelstore` database.
    *   Locate the document for the `admin` user.
    *   Edit the document and **add a new field**: `role` with the string value `admin`. Save the change.

### 2. Test as a Normal User

1.  Log in as `alice`. You will be prompted for your password again to decrypt your session keys.
2.  **Test Core Features:**
    *   **Upload:** Upload single or multiple files with different "Importance Levels".
    *   **Share:** Share a file with the `admin` user.
    *   **Download:** Download your own files.
    *   **Delete:** Securely delete a file by confirming with your password.

### 3. Test as an Admin

1.  Log out of the `alice` account.
2.  Log in as `admin`. You will be taken to the **Admin Dashboard**.
3.  **Test Admin Features:**
    *   **View Stats:** Observe the key metrics and charts.
    *   **Manage Users:** View the user list. You can delete the `alice` user from here.
    *   **Test GC:** After deleting a file as a user, come back to the admin panel and trigger the "Garbage Collection" to see the "Stored Shares" count decrease on the P2P nodes.

---

## 🔮 Future Work: Milestone 6 - The AI Guardian

The next major step is to implement the AI Guardian service, which will:
*   Analyze the rich data from the `logs` collection to build behavioral models for each user.
*   Provide real-time risk scores for actions like login and file sharing to prevent account takeover.
*   Use the P2P node `/health` endpoints to monitor network stability and trigger proactive self-healing operations.
