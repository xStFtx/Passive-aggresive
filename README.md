# Process IP Scanner

A tool designed to capture IP traffic for a specific process and conduct scans using `nmap`.

## Table of Contents

- [Process IP Scanner](#process-ip-scanner)
  - [Table of Contents](#table-of-contents)
  - [Installation](#installation)
  - [Usage](#usage)
  - [Features](#features)
  - [Contribute](#contribute)
  - [License](#license)

## Installation

1. Ensure you have Python and PyQt5 installed.
2. Install the required packages:

   ```bash
   pip install psutil pyshark
   ```

3. Clone this repository:

   ```bash
   git clone https://github.com/xStFtx/Passive-aggresive.git
   cd Passive-aggresive
   ```

## Usage

Run the tool using:

```bash
python main.py
```

1. Select the process from the dropdown.
2. Select the network interface.
3. Click "Scan IPs" to begin the scan.

## Features

- Real-time detection of processes running on your system.
- Captures IP traffic for the selected process.
- Uses `nmap` to scan detected IPs.
- Intuitive GUI powered by PyQt5.

## Contribute

1. Fork the repository.
2. Create a new branch for your changes.
3. Commit changes and open a pull request.

Feel free to report any issues or suggest new features!

## License

[MIT License](LICENSE)
