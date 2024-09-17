# Subdomain Enumeration Tool

A powerful, asynchronous subdomain enumeration tool built with Python, utilizing `aiohttp`, `aiodns`, and `asyncio` for fast and efficient subdomain discovery.

## Features

- Asynchronous DNS resolution and HTTP status checking for subdomains.
- Configurable concurrency for stability and performance.
- Automatic retries with exponential backoff for failed DNS queries.
- Output results in a clear, organized table format.
- Save results to a file.

## Installation

### Prerequisites

- Python 3.7 or higher
- Virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate  # On Windows use: .venv\Scripts\activate

### Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/4xyy/Subdomain-Enumeration-Tool.git
   cd Subdomain-Enumeration-Tool 
pip install -r requirements.txt
python subdomain_enum.py <domain> <wordlist.txt>
Options
--output <file>: Save found subdomains to the specified file.
--concurrency <number>: Set the number of concurrent requests (default is 10).
Example with Options:
python subdomain_enum.py example.com wordlist.txt --output results.txt --concurrency 20

Output
Results are displayed in a table format showing the subdomain, status, and reachability:

Subdomain        	Status	Reachability
found.example.com	200	Reachable via HTTP
unresolved.example.com		Not reachable

License
This project is licensed under the MIT License - see the LICENSE file for details.

Contributing
Contributions are welcome! Please fork the repository and submit a pull request for any enhancements or bug fixes.

Issues
If you encounter any issues or have feature requests, please open an issue in the GitHub repository.


