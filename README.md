# OSCP Initial Recon Script

`initial-recon.sh` is a Bash script designed for network reconnaissance and enumeration. It performs ping sweeps, port scans, service enumeration, and optional brute-force attacks on specified targets. The script supports both single IPs, IP ranges, CIDR notation, and target lists from a file, with customizable output directories and wordlists for brute-forcing. This was specifically crafted for the OSCP exam so customization may be required for other usage.

## Features
- **Ping Sweep**: Identifies live hosts using `fping`.
- **Port Scanning**: Performs fast TCP/UDP scans (`nmap`) and full SYN scans.
- **Service Enumeration**: Enumerates services (e.g., HTTP, FTP, SMB, SNMP) with tools like `nmap`, `enum4linux-ng`, `whatweb`, `wpscan`, and `feroxbuster`.
- **Web Enumeration**: Includes default directory enumeration with `feroxbuster` and WordPress scanning with `wpscan` for HTTP/HTTPS services.
- **Brute-Forcing**: Optional credential brute-forcing with `hydra`, `medusa`, `wpscan`, and `ncrack` (enabled with `--brute-enabled`).
- **Customizable Input/Output**: Supports target files, custom username/password wordlists, and custom output directories.
- **Organized Output**: Stores results in per-IP directories, with `10.*` IPs grouped under an `ad_set` directory.
- **Vulnerability Scanning**: Uses `searchsploit` to identify potential vulnerabilities based on `nmap` version scan results.

## Requirements
- **Operating System**: Linux (tested on Kali/Parrot OS).
- **Dependencies**:
  - `fping`
  - `nmap`
  - `enum4linux-ng`
  - `searchsploit`
  - `whatweb`
  - `wpscan`
  - `feroxbuster`
  - `hydra`
  - `medusa`
  - `ncrack`
  - `smbclient`
  - `smbmap`
  - `ldapsearch`
  - `onesixtyone`
  - `snmpwalk`
  - `smtp-user-enum`
- **Default Wordlists** (can be overridden):
  - Username: `/usr/share/seclists/Usernames/Names/names.txt`
  - Password: `/usr/share/wordlists/seclists/Passwords/xato-net-10-million-passwords-10000.txt`

## Usage
```bash
./initial-recon.sh [options] <targets> OR set $targets variable
```

### Required Options
One of the following must be specified:
- `--brute-enabled`: Enables brute-force attacks for supported services (e.g., FTP, HTTP, SSH, RDP).
- `--brute-disabled`: Disables brute-force attacks (default).

### Optional Options
- `--targets-file <file>`: Read targets from a file (one IP or range per line).
- `--wordlist-users <file>`: Custom username wordlist (default: `/usr/share/seclists/Usernames/Names/names.txt`).
- `--wordlist-pass <file>`: Custom password wordlist (default: `/usr/share/wordlists/seclists/Passwords/xato-net-10-million-passwords-10000.txt`).
- `--output-dir <dir>`: Custom output directory (default: current directory `.`).
- `--help`: Display usage information and exit.

### Example Commands
```bash
# Run with a single IP, default settings
./initial-recon.sh --brute-disabled 192.168.1.100

# Run with a target file and custom output directory
./initial-recon.sh --targets-file targets.txt --output-dir /path/to/output --brute-disabled

# Run with CIDR, custom wordlists, and brute-forcing enabled
./initial-recon.sh --brute-enabled --wordlist-users custom_users.txt --wordlist-pass custom_pass.txt 192.168.1.0/24

# Run with IP range
./initial-recon.sh --brute-disabled 192.168.1.141-145

# Display help
./initial-recon.sh --help
```

## Output Structure
- Output is stored in the specified `--output-dir` (default: `.`).
- For IPs starting with `10.*`, results are stored in `<output-dir>/ad_set/<ip>/`.
- For other IPs, results are stored in `<output-dir>/<ip>/`.
- Key files include:
  - `ping_sweep.txt`: Live hosts from the initial ping sweep.
  - `<ip>/nmap_fast.txt`: Fast TCP scan results.
  - `<ip>/nmap_udp.txt`: UDP scan results (port 161).
  - `<ip>/nmap_syn.txt`: Full TCP SYN scan results.
  - `<ip>/nmap_version.xml`: Version scan results.
  - `<ip>/searchsploit.txt`: Vulnerability scan results.
  - `<ip>/*.nmap`: Service-specific `nmap` results (e.g., `ftp`, `http`, `smb`).
  - `<ip>/*_ferox_*`: Directory enumeration results from `feroxbuster`.
  - `<ip>/*_wpscan_*`: WordPress enumeration results from `wpscan`.
  - `<ip>/*_brute_*`: Brute-force results (if `--brute-enabled`).

## Notes
- The script assumes the presence of default wordlists from SecLists. Ensure these are installed or provide custom wordlists.
- Brute-forcing (`--brute-enabled`) significantly increases scan time and should be used cautiously in authorized environments.
- The script runs multiple processes in parallel to improve efficiency but may require significant system resources.
- Ensure you have permission to scan target networks, as unauthorized scanning may violate laws or policies.

## License
This script is provided as-is for educational and authorized use only. Use responsibly and in compliance with applicable laws and regulations.
