# Network Reconnaissance Script

## Description
This Bash script (`initial-recon.sh`) automates network reconnaissance for penetration testing or security assessments. It performs ping sweeps, port scanning, service version detection, vulnerability scanning, and service-specific enumeration on a target network (CIDR or IP range). Key features include:
- **Ping sweep** to identify live hosts using `fping`.
- **Port scanning** with `nmap` (fast TCP, UDP, full TCP).
- **Version scanning** with `nmap`, outputting to both text and XML, followed by `searchsploit` for exploit matching.
- **Vulnerability scanning** using `nmap` scripts.
- **Active Directory enumeration** with `enum4linux-ng`, including RID brute-forcing (500-1000 range).
- **Service-specific enumeration** for protocols like FTP, HTTP, HTTPS, SMB, LDAP, SNMP, SSH, and more, using tools like `whatweb`, `wpscan`, and `feroxbuster` for web services.

The script organizes output into directories per IP under an `ad_set` folder, storing results in text files (e.g., `nmap_version.txt`, `enum4.txt`, `searchsploit.txt`).

## Requirements
Ensure the following tools are installed on a Linux system (e.g., Kali Linux):
- **fping**: For ping sweeps (`sudo apt install fping`).
- **nmap**: For port, version, and vulnerability scanning (`sudo apt install nmap`).
- **enum4linux-ng**: For Active Directory enumeration (`sudo apt install enum4linux-ng`).
- **searchsploit**: For exploit matching (`sudo apt install exploitdb`).
- **hydra**: For brute-forcing FTP and SSH (`sudo apt install hydra`).
- **medusa**: For brute-forcing HTTP, SSH, and Telnet (`sudo apt install medusa`).
- **whatweb**: For web technology fingerprinting (`sudo apt install whatweb`).
- **wpscan**: For WordPress enumeration (`sudo apt install wpscan`).
- **feroxbuster**: For web directory enumeration (`sudo apt install feroxbuster`).
- **smbclient**: For SMB share enumeration (`sudo apt install smbclient`).
- **smbmap**: For SMB mapping (`sudo apt install smbmap`).
- **ldapsearch**: For LDAP enumeration (`sudo apt install ldap-utils`).
- **ncrack**: For RDP brute-forcing (`sudo apt install ncrack`).
- **smtp-user-enum**: For SMTP user enumeration (`sudo apt install smtp-user-enum`).
- **onesixtyone** and **snmpwalk**: For SNMP enumeration (`sudo apt install snmp`).

Additionally:
- Wordlists: Ensure `/usr/share/seclists` and `/usr/share/wordlists` are available (install `seclists` and `rockyou.txt` on Kali).
- Permissions: Run as a user with sufficient permissions (sudo recommended for some tools).
- Network access: Ensure the system can reach the target network.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/<your-username>/<your-repo>.git
   cd <your-repo>
   ```
2. Make the script executable:
   ```bash
   chmod +x initial-recon.sh
   ```
3. Install dependencies (on Kali Linux):
   ```bash
   sudo apt update
   sudo apt install fping nmap enum4linux-ng exploitdb hydra medusa whatweb wpscan feroxbuster smbclient smbmap ldap-utils ncrack smtp-user-enum snmp seclists
   ```

## Usage
Run the script with a target IP range (CIDR or hyphenated range):
```bash
./initial-recon.sh <targets>
```
Examples:
- CIDR: `./initial-recon.sh 192.168.157.0/24`
- IP range: `./initial-recon.sh 192.168.157.141-145`

Alternatively, set the `targets` environment variable:
```bash
export targets="192.168.157.0/24"
./initial-recon.sh
```

The script will:
1. Perform a ping sweep to identify live hosts.
2. Run `nmap` scans (fast TCP on top 100 ports, UDP on port 161, full TCP).
3. Extract open ports for version and vulnerability scans.
4. Perform version scanning with `nmap -sV`, saving to `nmap_version.txt` and `nmap_version.xml`.
5. Run `searchsploit --nmap` on the XML output, saving to `searchsploit.txt`.
6. Conduct vulnerability scanning with `nmap --script=vuln`.
7. Enumerate Active Directory with `enum4linux-ng -R 500-1000`.
8. Perform service-specific enumeration for detected services (e.g., FTP, HTTP, SMB).

## Output Structure
Results are stored in the `ad_set` directory, with subdirectories for each live IP (e.g., `ad_set/192.168.157.141`). Example files per IP:
- `nmap_fast.txt`: Fast TCP scan results (top 100 ports).
- `nmap_udp.txt`: UDP scan results (port 161).
- `nmap_syn.txt`: Full TCP scan results (all ports).
- `nmap_version.txt`: Version scan results.
- `nmap_version.xml`: Version scan XML for `searchsploit`.
- `searchsploit.txt`: Exploit matches from `searchsploit --nmap`.
- `nmap_vuln.txt`: Vulnerability scan results.
- `enum4.txt`: Active Directory enumeration results with RID brute-forcing.
- Service-specific files (e.g., `<IP>_ftp_21.nmap`, `<IP>_http_80.nmap`, `<IP>_whatweb_80`, `<IP>_wpscan_80`, `<IP>_smbclient`).

Temporary files (`temp_ports.txt`) are cleaned up after execution. No `urls.txt` or `open_ports.txt` files are created.

## Example CLI Output
```bash
[+] Checking for targets input
[+] Performing ping sweep on 192.168.157.0/24
[+] Extracting live hosts
[+] Live hosts found: 192.168.157.141 192.168.157.143 192.168.157.144 192.168.157.145
[+] Creating ad_set directory and files
[+] Creating directories for live hosts
[+] Starting port scans
[+] Scanning 192.168.157.141 (fast TCP, UDP, full TCP)
...
[+] Waiting for port scans to complete
[+] Extracting open ports for version and vulnerability scans
[+] Starting version scanning
[+] Version scanning 192.168.157.141 on ports <ports>
...
[+] Running searchsploit on version scan results
[+] Running searchsploit on 192.168.157.141 version scan results
...
[+] Starting enum4linux-ng enumeration with RID brute-forcing
[+] Running enum4linux-ng on 192.168.157.141 with RID brute-forcing (500-1000)
...
[+] Reconnaissance complete
```

## Notes
- **Permissions**: Some tools (e.g., `nmap`, `hydra`) may require `sudo`. Run the script with elevated privileges if needed.
- **Performance**: The script runs scans in parallel to save time but may be resource-intensive for large networks. Adjust concurrency by serializing commands if necessary.
- **RID Brute-Forcing**: The `enum4linux-ng -R 500-1000` range targets common user RIDs. Modify the range (e.g., `-R 1000-2000`) in the script for different environments.
- **searchsploit**: Results in `searchsploit.txt` list potential exploits based on service versions. Review these manually for relevance.
- **Wordlists**: The script uses `/usr/share/seclists` and `/usr/share/wordlists/rockyou.txt`. Ensure these are present or adjust paths in the script.
- **Cleanup**: Temporary files (`temp_ports.txt`) are removed automatically. Check `ad_set/<IP>` for all persistent results.
- **Safety**: Use only on networks you have explicit permission to scan. Unauthorized scanning may violate laws or policies.

## Troubleshooting
- **Missing tools**: Install all required tools listed in Requirements.
- **Errors in `enum4linux-ng`**: Verify SMB services are accessible and adjust the RID range if needed.
- **No `searchsploit` results**: Check `nmap_version.xml` for valid service/version data.
- **File not found**: Ensure wordlists and tools are in the expected paths (`/usr/share/seclists`, `/usr/share/wordlists`).
- If issues persist, run with `bash -x ./initial-recon.sh` for debug output and share the results.

## License
Open-Source.

## Contributing
Submit issues or pull requests to the repository for improvements or bug fixes.
