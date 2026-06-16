# SubFinder 🔍

A fast, lightweight subdomain enumeration tool written in Python. Discover subdomains of any target domain using DNS resolution with multi-threaded scanning.

```
  ███████╗██╗   ██╗██████╗ ███████╗██╗███╗   ██╗██████╗ ███████╗██████╗ 
  ██╔════╝██║   ██║██╔══██╗██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗
  ███████╗██║   ██║██████╔╝█████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
  ╚════██║██║   ██║██╔══██╗██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
  ███████║╚██████╔╝██████╔╝██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║
  ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝
```

---

## ⚡ Features

- **Fast** — Multi-threaded DNS resolution (configurable thread count)
- **Dual engine** — Uses `dnspython` for accuracy; falls back to `socket` if unavailable
- **Built-in wordlist** — Works out of the box with 100+ common subdomains
- **Custom wordlists** — Bring your own wordlist file
- **Progress bar** — Real-time progress with elapsed time
- **Output to file** — Save discovered subdomains for later
- **Verbose mode** — See every check, not just hits
- **Color-coded output** — Clean terminal UI
- **No external API needed** — Pure DNS-based, works offline

---

## 📋 Requirements

- Python 3.7+
- `dnspython` (optional but recommended)

---

## 🚀 Installation

```bash
# 1. Clone the repository
git clone https://github.com/yourname/subfinder.git
cd subfinder

# 2. Install dependencies (optional but recommended)
pip install -r requirements.txt
```

> Without `dnspython`, the tool automatically falls back to Python's built-in `socket` module — no install required.

---

## 🛠 Usage

### Basic scan (built-in wordlist)
```bash
python subfinder.py -d example.com
```

### Custom wordlist
```bash
python subfinder.py -d example.com -w wordlists/common.txt
```

### Save results to file
```bash
python subfinder.py -d example.com -o results.txt
```

### Increase thread count for faster scanning
```bash
python subfinder.py -d example.com -t 100
```

### Verbose mode (see every checked subdomain)
```bash
python subfinder.py -d example.com -v
```

### Full example
```bash
python subfinder.py -d example.com -w wordlists/common.txt -t 80 -o output.txt -v
```

---

## ⚙️ Options

| Flag | Long | Description | Default |
|------|------|-------------|---------|
| `-d` | `--domain` | Target domain (required) | — |
| `-w` | `--wordlist` | Path to custom wordlist file | Built-in list |
| `-t` | `--threads` | Number of concurrent threads | `50` |
| `-o` | `--output` | Save results to a file | None |
| `-v` | `--verbose` | Show all checks, not just found | Off |
| | `--no-banner` | Suppress ASCII banner | Off |

---

## 📁 Project Structure

```
subfinder/
├── subfinder.py          # Main tool
├── requirements.txt      # Python dependencies
├── wordlists/
│   └── common.txt        # Built-in wordlist (editable)
├── .gitignore
└── README.md
```

---

## 📄 Output Format

Discovered subdomains are printed to the terminal and optionally saved:

**Terminal:**
```
  [+] dev.example.com                           93.184.216.34
  [+] mail.example.com                          93.184.216.35
  [+] api.example.com                           CNAME → api-lb.example.com
```

**File (`-o results.txt`):**
```
# SubFinder results — 2024-06-15 14:30:00
dev.example.com     93.184.216.34
mail.example.com    93.184.216.35
api.example.com     CNAME → api-lb.example.com
```

---

## 📝 Custom Wordlists

You can use any wordlist — one subdomain per line. Lines starting with `#` are treated as comments.

**Example:**
```
# My custom wordlist
www
api
admin
staging
dev
```

Popular community wordlists that work well with SubFinder:
- [SecLists DNS Wordlists](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)
- [Jhaddix all.txt](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)

---

## 🔧 Tips

- Start with **50–100 threads** for most targets; reduce if you hit rate limits
- Use a **large wordlist** (10k+ words) for thorough enumeration
- Combine with tools like `httpx` or `nmap` to probe discovered subdomains further
- Always ensure you have **permission** to scan the target domain

---

## ⚠️ Legal Disclaimer

This tool is intended for **authorized security testing and educational purposes only**. Scanning domains without explicit permission from the owner may be illegal. The author is not responsible for any misuse or damage caused by this tool.

**Only scan domains you own or have written permission to test.**

---

## 🤝 Contributing

Pull requests are welcome! To contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

---

## 📜 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## 🌟 Acknowledgements

- Inspired by tools like [Sublist3r](https://github.com/aboul3la/Sublist3r) and [amass](https://github.com/owasp-amass/amass)
- DNS resolution powered by [dnspython](https://www.dnspython.org/)
