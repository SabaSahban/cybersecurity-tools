# Cybersecurity Tools

This repository contains three key cybersecurity tools developed in Python. These tools focus on network security and password management, aimed at enhancing understanding of network vulnerabilities, password security, and encryption.

## Tools Included

### 1. Password Strength Evaluator & Brute Force Cracker
- **Description**: Evaluates password strength according to NIST standards. Additionally, it includes a brute force tool to crack passwords, simulating real-world attacks.
- **Features**:
  - Password strength evaluation based on NIST standards.
  - Brute force attack simulation, supporting modes with or without partial knowledge of the password.
  
### 2. Network Scanner
- **Description**: A network scanning tool that identifies active machines and open ports within a network.
- **Features**:
  - IP range scanning to detect live hosts.
  - TCP and UDP port scanning to identify open ports.
  - Service identification on open ports.
  - Generates reports in `txt` format for easy analysis.

### 3. Encrypted Password Manager
- **Description**: A secure password manager that allows users to generate and manage complex passwords.
- **Features**:
  - Password generation based on a user-provided simple password.
  - AES encryption to store passwords securely.
  - CRUD operations (create, read, update, delete) for managing passwords.
  - Stored passwords are encrypted and can only be accessed using the original simple password.
