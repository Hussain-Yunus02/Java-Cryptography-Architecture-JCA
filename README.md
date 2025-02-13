# Java Cryptography Architecture JCA
 This project is a cybersecurity initiative that shows the implementation and importance of different cybersecurity approaches (1- Shared key, 2-Public and Private Key, 3-Authentication Signatures)

Here’s a detailed and professional **README.md** file for your GitHub repository based on the lab:

---

# **COE817 - Lab 2: Java Cryptography & Authentication Protocols**

## **Overview**
This lab explores **Java Cryptography Architecture (JCA)** and its implementation in authentication protocols. It provides hands-on experience with **symmetric and asymmetric encryption**, **digital signatures**, and **secure communication protocols** using Java’s cryptography libraries. 

The lab is divided into **three projects**, each covering different aspects of cryptographic security:

1. **Symmetric Key-Based Authentication Protocol (AES/DES)**
2. **Public Key-Based Authentication Protocol (RSA)**
3. **Digital Signatures & Replay Attack Mitigation**

## **Technologies & Concepts**
- **Java Cryptography Architecture (JCA)**
- **Java Security & Cryptography Libraries (`java.security.*`, `javax.crypto.*`)**
- **Symmetric Encryption (AES, DES)**
- **Asymmetric Encryption (RSA)**
- **Digital Signatures**
- **Nonces & Authentication Protocols**
- **Socket Programming for Secure Communication**

---
## **Project 1: Symmetric Key-Based Authentication Protocol**
This project implements an **authentication protocol using symmetric encryption (AES/DES)** to securely exchange messages between two parties (**Alice & Bob**) over a Java socket connection.

### **Protocol Steps:**
1. **Alice → Bob**: Alice sends her identity and a randomly generated nonce (`NA`).
2. **Bob → Alice**: Bob responds with his own nonce (`NB`) and an encrypted message containing Bob’s identity and `NA`, encrypted with a shared symmetric key (`K_AB`).
3. **Alice → Bob**: Alice verifies `NA`, then encrypts and sends her identity along with `NB` back to Bob.

### **Implementation Details:**
- **AES/DES encryption** ensures message confidentiality.
- **Nonces prevent replay attacks** by ensuring messages are unique.
- **Java sockets (`ServerSocket` & `Socket`)** facilitate secure message exchange.

---
## **Project 2: Public Key-Based Authentication Protocol**
This project replaces **symmetric encryption with RSA**, an asymmetric cryptographic technique. Each party generates an **RSA key pair (public & private keys)** to securely authenticate.

### **Protocol Steps:**
1. **Alice → Bob**: Alice sends her identity and a nonce (`NA`).
2. **Bob → Alice**: Bob encrypts `NA` with Alice's **public key**, generates his own nonce (`NB`), and sends both back.
3. **Alice → Bob**: Alice decrypts `NA`, verifies it, then encrypts `NB` using Bob’s **public key** and sends it.

### **Implementation Details:**
- **RSA key pairs** are generated using `KeyPairGenerator` from `java.security.*`.
- **Encryption & decryption** are performed using `Cipher` from `javax.crypto.*`.
- **Java sockets enable secure client-server communication**.

---
## **Project 3: Digital Signatures & Replay Attack Mitigation**
This project implements **digital signatures** for authentication, ensuring **message integrity** and **sender authenticity**.

### **Protocol Steps:**
1. **Alice → Bob**: Alice sends a message (`M`) along with its **digital signature (`Sig_A(M)`)**.
2. **Bob** verifies the signature using Alice’s **public key**.

### **Implementation Details:**
- **Signature creation (`Sig_A(M)`)**: Alice signs the message using her **private key**.
- **Verification (`Verify(M, Sig_A(M))`)**: Bob verifies the signature with Alice’s **public key**.
- **Replay Attack Prevention**: A **timestamp** or **nonce** can be appended to each message to prevent attackers from resending a previously intercepted message.


## **Demonstration & Results**
### **Expected Outputs**
For each protocol, the program will display:
- **Sent & received messages**
- **Decryption results**
- **Signature verification status**
- **Error handling for invalid messages**

---
## **Enhancements & Future Work**
- Implement **Hybrid Encryption** (AES + RSA) for efficiency.
- Extend **signature-based authentication** with **timestamping** for stronger security.
- Use **TLS-based Java Sockets** for real-world secure communication.

---
## **References**
- [Java Cryptography Architecture (JCA) Guide](https://docs.oracle.com/en/java/javase/21/security/java-cryptography-architecture-jca-reference-guide.html)
- [Java Secure Sockets API](https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html)

---
## **Author**
**Husain Yunus Maudiwala**  
*5th-year Computer Engineering Student @ Toronto Metropolitan University*  
