# Go-TLS-Client-with-Concurrent-SHA-1-Proof-of-Work-Solver
A Go-based TLS client that connects to a secure server, performs mutual authentication, and solves SHA-1 Proof-of-Work challenges using multi-core parallelism. Optimized with goroutines, atomic operations, and concurrent hash computation.
# Go TLS Client with Concurrent SHA-1 Proof-of-Work Solver

## 🔹 Overview
This project implements a **Go-based TLS client** that connects to a secure server and solves **SHA-1 Proof-of-Work (PoW) challenges**. It uses **multi-core concurrency** with goroutines and atomic operations to optimize hash computation. The client also supports **mutual TLS authentication** and secure certificate validation.

---

## 🔹 Features
- TLS mutual authentication with client and CA certificates
- SHA-1 based Proof-of-Work solver
- Multi-core parallelism using **goroutines**
- Atomic synchronization to ensure thread-safe operations
- Real-time server challenge handling
- Configurable difficulty for PoW challenges

---

## 🔹 Architecture / Flow Diagram

```text
               +----------------+
               |   Remote TLS   |
               |    Server      |
               +-------+--------+
                       |
                       | Challenge (POW)
                       v
              +------------------+
              | Go TLS Client    |
              |                  |
              | 1. Read Server   |
              |    Challenge     |
              | 2. Solve POW     |
              |    Concurrently  |
              | 3. Send Response |
              +------------------+
                       |
                       v
               +----------------+
               | Server Verifies |
               +----------------+
