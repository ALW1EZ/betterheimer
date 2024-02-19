# BetterHeimer

BetterHeimer is a Python-based application designed to scan Minecraft servers within a specified network range. It provides a graphical user interface (GUI) for easy interaction with the scanning and checking functionality.

## Features

- **Network Scanning**: Scan a range of IP addresses for Minecraft servers and retrieve information such as the server version, MOTD, number of players online, and player names.
- **Version Filtering**: Filter the scan results based on the server version, allowing you to focus on specific versions of Minecraft.
- **Player Filtering**: Include or exclude servers based on whether they have players online.
- **Concurrent Scanning**: Utilize multiple threads to scan servers concurrently, speeding up the process.
- **Check Module**: Run checks on a list of IP addresses using a Node.js script ([mineflayer](https://github.com/PrismarineJS/mineflayer)), providing additional information about can cracked clients connect to server.
- **GUI**: A user-friendly interface for managing scans and viewing results (right click table for more options like saving ips and sorting by version).

## Getting Started

### Prerequisites

- Python 3.11 (recommended)
- PyQt5 for the GUI
- [mcstatus](https://github.com/py-mine/mcstatus) for querying Minecraft servers
- Node.js (optional, for the check module)

### Installation

1. Clone the repository:
`git clone https://github.com/ALW1EZ/betterheimer.git`

3. Change into the project directory:
`cd betterheimer`

4. Create a virtual environment and activate it:
`python3 -m venv .venv`
`source .venv/bin/activate`

5. Install the required Python packages:
`pip install -r requirements.txt`

6. If you plan to use the check module, ensure Node.js is installed and available in your PATH.
   Change directory to check/ folder and install mineflayer for check module.
`cd check`
`npm install mineflayer`
   You can go back now.
`cd ..`

### Usage

1. Run the application:
`python betterheimer.py`
