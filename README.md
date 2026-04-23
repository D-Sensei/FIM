# File Integrity Monitor

A focused, host-based file integrity monitoring (FIM) tool designed for correctness, clarity, and system control. 

Instead of bloated enterprise suites, this utility provides a transparent way to baseline your filesystem, detect unauthorized changes, and log events using a robust SQLite backend.

---

## 核心 (The Core Logic)

At its heart, the Sentinel follows a simple but rigorous workflow:
1. **Baseline:** Generate a "known-good" state of your files using cryptographic hashes.
2. **Detect:** Re-scan the environment to identify modifications, deletions, or unexpected "ghost" files.
3. **Audit:** Log every event into a structured database designed for long-term usability.

## Key Features

* **Chunk-Based Hashing:** Processes files in 8KB increments to maintain a low memory footprint. Supports `SHA-256`, `SHA-1`, and `MD5`.
* **SQLite Storage:** Uses a relational backend for the baseline and event logs. This ensures scalability and complex querying—something JSON simply can't handle.
* **Recursive Scanning:** Deep-directory traversal with granular ignore controls (regex/path-based).
* **Real-Time Monitoring:** Integrated with `watchdog` to catch filesystem events the moment they happen.
* **CLI-Driven:** A clean command-line interface for manual scans, baselining, and log exports.

## Why this exists?
This isn't "enterprise-grade" by design. It was built for users who value **understanding over abstraction**. It gives you total control over the integrity of your host without the overhead of proprietary monitoring agents.

---

## 🛠 Tech Stack
* **Language:** Python 3.x
* **Database:** SQLite3
* **Monitoring:** Watchdog API
* **Hashing:** Hashlib (Iterative implementation)

---

## 🚀 Roadmap (The Parts That Matter)

The project is evolving with a focus on scaling and security:

- [ ] **Parallel Hashing:** Implementing multi-threading to handle massive datasets without the single-threaded bottleneck.
- [ ] **Config System:** Moving away from hardcoded defaults to a persistent, flexible configuration file.
- [ ] **Threat Intelligence:** Integrating external APIs and threat feeds to flag known malicious hashes.
- [ ] **Alerting:** Real-time notifications (Webhooks, Email, or Desktop alerts).
- [ ] **DB Protection:** Implementing integrity checks on the SQLite database itself to prevent tampering.
- [ ] **UI Layer:** A lightweight dashboard for visual log analysis (Low priority).

---

## 📸 Screenshots

### 1. Operations & Logs
<p align="center">
  <img src="Resource/Images/FIM1.png" width="48%" alt="Baseline Generation" />
  <img src="Resource/Images/FIM2.png" width="48%" alt="Integrity Violation Detection" />
</p>

<p align="center">
  <img src="Resource/Images/FIM3.png" width="48%" alt="Audit Logs" />
  <img src="Resource/Images/FIM44.png" width="48%" alt="Configuration View" />
</p>

### 2. Real-Time Monitoring
<p align="center">
  <img src="Resource/Images/fim5.png" width="90%" alt="Real-time Watchdog Monitor" />
</p>

---

## 🚀 Quick Start

```bash
# Generate a baseline for a directory
python fim.py 

# To know Functionality
help
python fim.py baseline -p C:/user/../file.dump --algo sha256
python fim.py scan
python fim.py live -p C:/folder
