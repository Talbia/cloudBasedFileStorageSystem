# Secure Cloud-Based File Storage and Sharing System
This repository contains the implementation of a Secure Cloud-Based File Storage and Sharing System, developed as part of the CSIT953 – Emerging Topics in Cybersecurity course. The project integrates AES encryption, ECDSA digital signatures, and blockchain technology to ensure robust security for cloud file storage and sharing.

## Key Features
1. File Encryption and Decryption

    Utilizes AES (Advanced Encryption Standard) for encrypting files before uploading to the cloud.
    Ensures confidentiality, even if the cloud storage is compromised.
    Encrypted files are decrypted upon access approval, maintaining secure data flow.

2. Digital Signature and Verification

    Implements ECDSA (Elliptic Curve Digital Signature Algorithm) for signing files.
    Allows users to verify file authenticity and integrity before access.

3. Blockchain-Based Record Keeping

    Uses smart contracts to log all transactions, ensuring transparency and traceability.
    Logs file uploads, access requests, approvals, and denials on the blockchain, creating an immutable ledger.

4. Secure Key Sharing

    Encrypts file encryption keys using the requester’s public key.
    Ensures secure key transfer and prevents unauthorized access.

5. User-Friendly Graphical User Interface (GUI)

    Provides an intuitive interface for file owners and requesters.
    Includes real-time status updates for uploads, requests, and blockchain transactions.

6. Cloud Integration

    Stores encrypted files on Google Cloud, combining scalability and strong security measures.

System Architecture

The system is built with the following core components:

    File Owner: Uploads encrypted files and approves/denies access requests.
    Requester: Submits access requests and decrypts approved files.
    Blockchain Network: Logs all file-related activities via smart contracts.
    Google Cloud: Backend repository for encrypted files.
    Smart Contracts:
        FileStorage Contract: Tracks metadata (e.g., file name, uploader ID).
        AccessManagement Contract: Automates access request and approval workflows.

Implementation Details

    Programming Languages and Tools:
        Python for encryption, decryption, and GUI implementation.
        Truffle framework for deploying smart contracts.
    Encryption: AES in CFB mode with unique Initialization Vectors (IVs).
    Digital Signature: ECDSA ensures non-repudiation and tamper-proof files.
    Blockchain: Deployed on Sepolia Testnet for logging immutable transactions.
