#!/bin/bash

echo "  .              .       .                 .                                 .          .           "
echo "                                             .       .                                              "
echo "                             .          .::::..      ..::::.                                        "
echo "                                .      .#@@@@@@*=--=*%@@@@@#.             .                .        "
echo "   .            ...                    -@@@@@@@@@@@@@@@@@@@@-                      .                "
echo "                                       *@@@@@@@@@@@@@@@@@@@@*                                       "
echo "                                      .@@@@@@@@@@@@@@@@@@@@@@.                            .     .   "
echo "                                     .=@@@@@@@@@@@@@@@@@@@@@@=                         .         .  "
echo "                 .               .   .*@@@@@@@@@@@@@@@@@@@@@@#.               . .                   "
echo "             .                       :%@@@@@@@@@@@@@@@@@@@@@@%:  .                                  "
echo ".            .   .      .:-===---=+**=@@@@@@@@@@@@@@@@@@@@@@@@=**+=---===-:.                        "
echo "                      .+@@@@@@@@@@@@#+@@@@@@@@@@@@@@@@@@@@@@@@+*@@@@@@@@@@@@+.                      "
echo "                . .   :%@@@@@@@@@@@@=    ..-==+******++=-..    =@@@@@@@@@@@@%:     .    .           "
echo "   .                  :#@@@@@@@@@@@@=:....  .   .         ....:=@@@@@@@@@@@@%:                      "
echo " .         .           :#@@@@@@@@@@@@@@@@@%%#**********#%%@@@@@@@@@@@@@@@@@#:                       "
echo "              .          :+%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%+:                         "
echo "   .   .  .    .           ..:=#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#=:..      .             .      "
echo " .                            .=%@@*:-+*#%@@@@@@@@@@@@@@@@%#*+-:+@@%+.      .                       "
echo "                          ..=@@@@@@%.*@@@%#*+===-----===+*#%@@*.%@@@@@@=..                       .  "
echo ".                        .+@@@@@@@@@--%@@@@@@@@@*:.+@@@@@@@@@@--@@@@@@@@@*:                         "
echo "  .       .   .     .  .+@@@@@@@@@@@*.-#@@@@@@@+.  .+@@@@@@@%-.*@@@@@@@@@@@*.         .             "
echo "                     .-%@@@@@@@@@@@@@-  .--=--..    ..--=--.  -%@@@@@@@@@@@@%-.                     "
echo "                     .-%@@@@@@@@@@@@@#:                      .#@@@@@@@@@@@@@%-.                     "
echo "          .           .:@@@@@@@@@@@@@@*.                    .+@@@@@@@@@@@@@@:                  .    "
echo "                 .      .+@@@@@@@@@@@@@*.   .        .     .*@@@@@@@@@@@@@+.                        "
echo "               .         ..+@@@@@@@@@@@@%:.              .:%@@@@@@@@@@@@+..            .            "
echo "        .                 .:-=#@@@@@@@@@@@*..          ..*@@@@@@@@@@@#=-:.                          "
echo " .          .          .-#@@@@%+=#@@@@@@@@@@#:        :#@@@@@@@@@@%=+%@@@@#-.                       "
echo "                     .*@@@@@@@@@@@%**@@@@@@@@@@#:..:#@@@@@@@@@@**%@@@@@@@@@@@*.  ..              .  "
echo "                   .*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*.    .              "
echo "                 .-@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@-.             .   "
echo ".                :#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%:                ."
echo "   .              .=@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@=.                  "
echo "      .           . .-%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%=.         .          "
echo "       .               .*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#.                       "
echo "           .             ..+%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*:.                         "
echo "                     .       .-+#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%*-.                             "
echo "    .    .                .      ..-=*#%@@@@@@@@@@@@@@@@@@@@@%*+-:.      ..      .        .         "
echo "         .                              ...:::--------::::..                             .        . "
echo "     ..                 .                                                        .                 ."


# Function to display usage and exit
usage() {
    echo "Usage: ./initial-recon.sh [options] <targets> OR set \$targets variable"
    echo "Required:"
    echo "  --brute-enabled         Enable brute-force attacks (default: disabled)"
    echo "  --brute-disabled        Disable brute-force attacks"
    echo "Options:"
    echo "  --targets-file <file>   Read targets from a file"
    echo "  --wordlist-users <file> Custom username wordlist (default: $user_wordlist)"
    echo "  --wordlist-pass <file>  Custom password wordlist (default: $pass_wordlist)"
    echo "  --output-dir <dir>      Custom output directory (default: $output_dir)"
    echo "  --help                  Display this help message and exit"
    exit 0
}

# Function to convert IP range (e.g., 192.168.1.141-145) to individual IPs
expand_ip_range() {
    local input=$1
    # Check if input contains a hyphen for range
    if [[ $input =~ ([0-9]+\.[0-9]+\.[0-9]+\.)([0-9]+)-([0-9]+) ]]; then
        prefix=${BASH_REMATCH[1]}
        start=${BASH_REMATCH[2]}
        end=${BASH_REMATCH[3]}
        # Generate list of IPs
        for ((i=start; i<=end; i++)); do
            echo "$prefix$i"
        done
    else
        # If not a range, assume CIDR or single IP
        echo "$input"
    fi
}

# Default options
brute_enabled=false
output_dir="."
user_wordlist="/usr/share/seclists/Usernames/Names/names.txt"
pass_wordlist="/usr/share/wordlists/seclists/Passwords/xato-net-10-million-passwords-10000.txt"
targets_file=""
targets=""

# Parse command-line options
while [[ $# -gt 0 ]]; do
    case $1 in
        --brute-enabled)
            brute_enabled=true
            shift
            ;;
        --brute-disabled)
            brute_enabled=false
            shift
            ;;
        --targets-file)
            targets_file="$2"
            shift 2
            ;;
        --wordlist-users)
            user_wordlist="$2"
            shift 2
            ;;
        --wordlist-pass)
            pass_wordlist="$2"
            shift 2
            ;;
        --output-dir)
            output_dir="$2"
            shift 2
            ;;
        --help)
            usage
            ;;
        *)
            # Assume remaining arguments are targets
            targets="${@:1}"
            break
            ;;
    esac
done

# Check if targets is set or file provided
echo "[+] Checking for targets input"
was_set=false
if [ -n "$targets_file" ]; then
    if [ -f "$targets_file" ]; then
        targets=$(cat "$targets_file" | tr '\n' ' ')
        echo "[+] Loaded targets from file: $targets"
    else
        echo "[-] Error: Targets file '$targets_file' not found"
        exit 1
    fi
elif [ -z "$targets" ]; then
    usage
fi

# Create output directory if it doesn't exist
mkdir -p "$output_dir" || { echo "[-] Error: Could not create output directory '$output_dir'"; exit 1; }

# Handle IP range or CIDR for ping sweep
echo "[+] Performing ping sweep on $targets"
if [[ $targets =~ [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+-[0-9]+ ]]; then
    # Convert range to list of IPs and store in a temporary file
    expand_ip_range "$targets" > "$output_dir/temp_ips.txt"
    fping -a -f "$output_dir/temp_ips.txt" 2>/dev/null > "$output_dir/ping_sweep.txt"
    rm "$output_dir/temp_ips.txt"
else
    # Assume CIDR or single IP (or space-separated multiples)
    fping -a -g $targets 2>/dev/null > "$output_dir/ping_sweep.txt"
fi

# Extract live hosts directly from ping_sweep.txt
echo "[+] Extracting live hosts"
live_hosts=$(cat "$output_dir/ping_sweep.txt")
if [ -z "$live_hosts" ]; then
    echo "[-] No live hosts detected in $targets."
    exit 1
fi
echo "[+] Live hosts found: $live_hosts"

# Create ad_set directory and files
echo "[+] Creating ad_set directory and files"
mkdir -p "$output_dir/ad_set"
touch "$output_dir/ad_set/usernames" "$output_dir/ad_set/passwords" "$output_dir/ad_set/credentials"

# Create directories for each live host
echo "[+] Creating directories for live hosts"
for ip in $live_hosts; do
    if [[ $ip =~ ^10\. ]]; then
        mkdir -p "$output_dir/ad_set/$ip"
        touch "$output_dir/ad_set/$ip/usernames" "$output_dir/ad_set/$ip/passwords" "$output_dir/ad_set/$ip/credentials"
    else
        mkdir -p "$output_dir/$ip"
        touch "$output_dir/$ip/usernames" "$output_dir/$ip/passwords" "$output_dir/$ip/credentials"
    fi
done

# Perform fast TCP and UDP scans in parallel
echo "[+] Starting fast TCP and UDP scans"
pids=()
for ip in $live_hosts; do
    if [[ $ip =~ ^10\. ]]; then
        targetdir="$output_dir/ad_set/$ip"
    else
        targetdir="$output_dir/$ip"
    fi
    echo "[+] Scanning $ip (fast TCP, UDP)"
    nmap -T4 "$ip" --top-ports 100 | tee "$targetdir/nmap_fast.txt" &
    pids+=($!)
    nmap -sU -T4 -p 161 "$ip" --open | tee "$targetdir/nmap_udp.txt" &
    pids+=($!)
done

# Wait for fast TCP and UDP scans to complete
echo "[+] Waiting for fast TCP and UDP scans to complete"
for pid in "${pids[@]}"; do
    wait "$pid"
done

# Run enum4linux-ng for all hosts in parallel with RID brute-forcing
echo "[+] Starting enum4linux-ng enumeration with RID brute-forcing"
pids=()
for ip in $live_hosts; do
    if [[ $ip =~ ^10\. ]]; then
        targetdir="$output_dir/ad_set/$ip"
    else
        targetdir="$output_dir/$ip"
    fi
    echo "[+] Running enum4linux-ng on $ip with RID brute-forcing (500-550)"
    enum4linux-ng -d -A -O -r 500-550 "$ip" > "$targetdir/enum4.txt" &
    pids+=($!)
done

# Wait for enum4linux-ng to complete
echo "[+] Waiting for enum4linux-ng to complete"
for pid in "${pids[@]}"; do
    wait "$pid"
done

# Perform SYN scan
echo "[+] Starting full TCP SYN scan"
pids=()
for ip in $live_hosts; do
    if [[ $ip =~ ^10\. ]]; then
        targetdir="$output_dir/ad_set/$ip"
    else
        targetdir="$output_dir/$ip"
    fi
    echo "[+] SYN scanning $ip (all ports)"
    nmap -sS -p- -T5 -v0 -oN "$targetdir/nmap_syn.txt" "$ip" > /dev/null &
    pids+=($!)
done

# Wait for SYN scans to complete
echo "[+] Waiting for SYN scans to complete"
for pid in "${pids[@]}"; do
    wait "$pid"
done

# Extract open ports for each target (for version and vulnerability scans)
echo "[+] Extracting open ports for version and vulnerability scans"
for ip in $live_hosts; do
    if [[ $ip =~ ^10\. ]]; then
        targetdir="$output_dir/ad_set/$ip"
    else
        targetdir="$output_dir/$ip"
    fi
    ports=$( (grep "/tcp.*open" "$targetdir/nmap_syn.txt" | awk '{print $1}' | cut -d/ -f1; grep "/udp.*open" "$targetdir/nmap_udp.txt" | awk '{print $1}' | cut -d/ -f1) | sort -nu | tr '\n' ',' | sed 's/,$//')
    echo "$ports" > "$targetdir/temp_ports.txt"
done

# Version scanning with XML output
echo "[+] Starting version scanning"
pids=()
for ip in $live_hosts; do
    if [[ $ip =~ ^10\. ]]; then
        targetdir="$output_dir/ad_set/$ip"
    else
        targetdir="$output_dir/$ip"
    fi
    ports=$(cat "$targetdir/temp_ports.txt")
    if [ -n "$ports" ]; then
        echo "[+] Version scanning $ip on ports $ports"
        nmap -sV -p "$ports" -oX "$targetdir/nmap_version.xml" "$ip" > /dev/null &
        pids+=($!)
    fi
done

# Wait for version scans
echo "[+] Waiting for version scans to complete"
for pid in "${pids[@]}"; do
    wait "$pid"
done

# Run searchsploit on version scan XML results
echo "[+] Running searchsploit on version scan results"
pids=()
for ip in $live_hosts; do
    if [[ $ip =~ ^10\. ]]; then
        targetdir="$output_dir/ad_set/$ip"
    else
        targetdir="$output_dir/$ip"
    fi
    if [ -f "$targetdir/nmap_version.xml" ]; then
        echo "[+] Running searchsploit on $ip version scan results"
        searchsploit --nmap "$targetdir/nmap_version.xml" > "$targetdir/searchsploit.txt" &
        pids+=($!)
    fi
done

# Wait for searchsploit to complete
echo "[+] Waiting for searchsploit to complete"
for pid in "${pids[@]}"; do
    wait "$pid"
done

# Function to run service-specific enumeration
run_commands_for_serv() {
    local ip=$1
    local port=$2
    local serv=$3
    local targetdir=$4
    local proto=$5

    pids=()

    echo "[+] Enumerating $serv on $ip:$port ($proto)"
    if [[ "$serv" == *"ftp"* || "$serv" == *"tftp"* ]]; then
        nmap -n -sV -Pn -p"$port" --script=ftp* -oN "$targetdir/${ip}_ftp_${port}.nmap" "$ip" > /dev/null &
        pids+=($!)
        if $brute_enabled; then
            hydra -L "$user_wordlist" -P "$pass_wordlist" -f -o "$targetdir/${ip}_ftphydra" -u "$ip" -s "$port" ftp &
            pids+=($!)
        fi
    elif [[ "$serv" == "http" || "$serv" == "http?" ]]; then
        nmap -n -sV -Pn -p"$port" --script=http-brute,http-svn-enum,http-svn-info,http-git,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-iis-webdav-vuln,http-vuln-cve2009-3960,http-vuln-cve2010-0738,http-vuln-cve2011-3368,http-vuln-cve2012-1823,http-vuln-cve2013-0156,http-waf-detect,http-waf-fingerprint,ssl-enum-ciphers,ssl-known-key -oN "$targetdir/${ip}_http_${port}.nmap" "$ip" > /dev/null &
        pids+=($!)
        nmap -n -sV -Pn -p"$port" --script=http-shellshock-spider -oN "$targetdir/${ip}_http_shellshock_${port}.nmap" "$ip" > /dev/null &
        pids+=($!)
        whatweb --color=never --no-errors "http://$ip:$port" > "$targetdir/${ip}_whatweb_${port}" &
        pids+=($!)
        wpscan --url "http://$ip:$port" -e ap,vt,cb,u > "$targetdir/${ip}_wpscan_${port}" &
        pids+=($!)
        feroxbuster --url "http://$ip:$port" -w /usr/share/wordlists/dirb/common.txt --extract-links --scan-limit 1 > "$targetdir/${ip}_ferox_common_${port}" &
        pids+=($!)
        feroxbuster --url "http://$ip:$port" -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt --extract-links --scan-limit 1 > "$targetdir/${ip}_ferox_medium_${port}" &
        pids+=($!)
        if $brute_enabled; then
            wpscan --url "http://$ip:$port" -P "$pass_wordlist" -U admin > "$targetdir/${ip}_wpscan_brute_${port}" &
            pids+=($!)
            medusa -U /usr/share/wordlists/metasploit/http_default_users.txt -P "$pass_wordlist" -e ns -h "$ip" -p "$port" -M http -m DIR:secret -f &
            pids+=($!)
        fi
    elif [[ "$serv" == "ssl/http" || "$serv" == *"https"* ]]; then
        nmap -n -sV -Pn -p"$port" --script=http-brute,http-svn-enum,http-svn-info,http-git,ssl-heartbleed,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-iis-webdav-vuln,http-vuln-cve2009-3960,http-vuln-cve2010-0738,http-vuln-cve2011-3368,http-vuln-cve2012-1823,http-vuln-cve2013-0156,http-waf-detect,http-waf-fingerprint,ssl-enum-ciphers,ssl-known-key -oN "$targetdir/${ip}_https_${port}.nmap" "$ip" > /dev/null &
        pids+=($!)
        nmap -n -sV -Pn -p"$port" --script=http-shellshock-spider -oN "$targetdir/${ip}_http_shellshock_${port}.nmap" "$ip" > /dev/null &
        pids+=($!)
        whatweb --color=never --no-errors "https://$ip:$port" > "$targetdir/${ip}_whatweb_https_${port}" &
        pids+=($!)
        wpscan --url "https://$ip:$port" -e ap,vt,cb,u > "$targetdir/${ip}_wpscan_https_${port}" &
        pids+=($!)
        feroxbuster --url "https://$ip:$port" --insecure -w /usr/share/wordlists/dirb/common.txt --extract-links --scan-limit 1 > "$targetdir/${ip}_ferox_https_common_${port}" &
        pids+=($!)
        feroxbuster --url "https://$ip:$port" --insecure -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt --extract-links --scan-limit 1 > "$targetdir/${ip}_ferox_https_medium_${port}" &
        pids+=($!)
        if $brute_enabled; then
            wpscan --url "https://$ip:$port" -P "$pass_wordlist" -U admin > "$targetdir/${ip}_wpscan_brute_${port}" &
            pids+=($!)
        fi
    elif [[ "$serv" == *"mongodb"* ]]; then
        nmap -n -sV -Pn -p "$port" --script=mongodb* -oN "$targetdir/${ip}_mongodb_${port}.nmap" "$ip" > /dev/null &
        pids+=($!)
    elif [[ "$serv" == *"oracle"* ]]; then
        nmap -n -sV -Pn -p "$port" --script=oracle* -oN "$targetdir/${ip}_oracle_${port}.nmap" "$ip" > /dev/null &
        pids+=($!)
    elif [[ "$serv" == *"mysql"* ]]; then
        nmap -n -sV -Pn -p "$port" --script=mysql* -oN "$targetdir/${ip}_mysql_${port}.nmap" "$ip" > /dev/null &
        pids+=($!)
    elif [[ "$serv" == *"ms-sql"* ]]; then
        nmap -n -sV -Pn -p"$port" --script=ms-sql-ntlm-info,ms-sql-brute,ms-sql-empty-password,ms-sql-info,ms-sql-config,ms-sql-dump-hashes -oN "$targetdir/${ip}_mssql_${port}.nmap" "$ip" > /dev/null &
        pids+=($!)
    elif [[ "$serv" == *"microsoft-ds"* || "$serv" == *"netbios-ssn"* ]]; then
        nmap -n -sV -Pn -pT:139,"$port",U:137 --script=smb-enum-shares,smb-enum-domains,smb-enum-groups,smb-enum-processes,smb-enum-sessions,smb-ls,smb-mbenum,smb-os-discovery,smb-print-text,smb-security-mode,smb-server-stats,smb-system-info,smb-vuln* -oN "$targetdir/${ip}_smb_${port}.nmap" "$ip" > /dev/null &
        pids+=($!)
        smbclient -L \\ -N -I "$ip" > "$targetdir/${ip}_smbclient" &
        pids+=($!)
        smbmap -u guest -H "$ip" -R > "$targetdir/${ip}_smbmap" &
        pids+=($!)
    elif [[ "$serv" == *"ldap"* ]]; then
        nmap -n -sV -Pn -p"$port" --script=ldap-search.nse -oN "$targetdir/${ip}_ldap_${port}.nmap" "$ip" > /dev/null &
        pids+=($!)
        ldapsearch -H ldap://"$ip" -x -LLL -s base -b "" supportedSASLMechanisms > "$targetdir/${ip}_ldapsearch_${port}" &
        pids+=($!)
    elif [[ "$serv" == *"msdrdp"* || "$serv" == *"ms-wbt-server"* ]]; then
        if $brute_enabled; then
            ncrack -vv --user Administrator -P "$pass_wordlist" rdp://"$ip" &
            pids+=($!)
        fi
    elif [[ "$serv" == *"smtp"* ]]; then
        nmap -n -sV -Pn -p"$port" --script=smtp* -oN "$targetdir/${ip}_smtp_${port}.nmap" "$ip" > /dev/null &
        pids+=($!)
        smtp-user-enum -M VRFY -U "$user_wordlist" -t "$ip" -p "$port" > "$targetdir/${ip}_smtp_enum_${port}" &
        pids+=($!)
    elif [[ "$serv" == *"snmp"* || "$serv" == *"smux"* ]]; then
        nmap -n -sU -sV -Pn -pU:"$port" --script=snmp-sysdescr,snmp-info,snmp-netstat,snmp-processes -oN "$targetdir/${ip}_snmp_${port}.nmap" "$ip" > /dev/null &
        pids+=($!)
        onesixtyone -c public "$ip" > "$targetdir/${ip}_161" &
        pids+=($!)
        snmpwalk -c public -v1 "$ip" > "$targetdir/${ip}_snmpwalk" &
        pids+=($!)
        snmpwalk -c public -v1 "$ip" 1.3.6.1.4.1.77.1.2.25 > "$targetdir/${ip}_snmp_users" &
        pids+=($!)
        snmpwalk -c public -v1 "$ip" 1.3.6.1.2.1.6.13.1.3 > "$targetdir/${ip}_snmp_ports" &
        pids+=($!)
        snmpwalk -c public -v1 "$ip" 1.3.6.1.2.1.25.4.2.1.2 > "$targetdir/${ip}_snmp_process" &
        pids+=($!)
        snmpwalk -c public -v1 "$ip" 1.3.6.1.2.1.25.6.3.1.2 > "$targetdir/${ip}_snmp_software" &
        pids+=($!)
        snmpwalk -c public -v1 "$ip" NET-SNMP-EXTEND-MIB::1nsExtendOutputFull > "$targetdir/${ip}_snmp_software" &
        pids+=($!)
    elif [[ "$serv" == *"ssh"* ]]; then
        if $brute_enabled; then
            medusa -u root -P "$pass_wordlist" -e ns -h "$ip" -p "$port" -M ssh -f &
            pids+=($!)
            medusa -U "$user_wordlist" -P "$pass_wordlist" -e ns -h "$ip" -p "$port" -M ssh -f &
            pids+=($!)
            hydra -f -V -t 1 -l root -P "$pass_wordlist" -s "$port" "$ip" ssh &
            pids+=($!)
        fi
    elif [[ "$serv" == *"telnet"* ]]; then
        if $brute_enabled; then
            medusa -U "$user_wordlist" -P "$pass_wordlist" -e ns -h "$ip" -p "$port" -M telnet -t1 -f &
            pids+=($!)
        fi
    elif [[ "$serv" == *"domain"* ]]; then
        nmap -n -sV -Pn -p"$port" --script=dns* -oN "$targetdir/${ip}_dns_${port}.nmap" "$ip" > /dev/null &
        pids+=($!)
    fi

    # Wait for this service's commands to complete
    echo "[+] Waiting for $serv enumeration on $ip:$port to complete"
    for pid in "${pids[@]}"; do
        wait "$pid"
    done
}

# Parse services and run enumerations
echo "[+] Starting service-specific enumerations"
for ip in $live_hosts; do
    if [[ $ip =~ ^10\. ]]; then
        targetdir="$output_dir/ad_set/$ip"
    else
        targetdir="$output_dir/$ip"
    fi

    # Parse TCP services from nmap_syn.txt
    grep "/tcp.*open" "$targetdir/nmap_syn.txt" | while read -r line; do
        port=$(echo "$line" | awk '{print $1}' | cut -d/ -f1)
        serv=$(echo "$line" | awk '{print $3}')
        run_commands_for_serv "$ip" "$port" "$serv" "$targetdir" "tcp"
    done

    # Parse UDP services from nmap_udp.txt
    grep "/udp.*open" "$targetdir/nmap_udp.txt" | while read -r line; do
        port=$(echo "$line" | awk '{print $1}' | cut -d/ -f1)
        serv=$(echo "$line" | awk '{print $3}')
        run_commands_for_serv "$ip" "$port" "$serv" "$targetdir" "udp"
    done
done

# Wait for any remaining pids
echo "[+] Waiting for remaining tasks to complete"
for pid in "${pids[@]}"; do
    wait "$pid" 2>/dev/null
done

# Clean up temporary port files
echo "[+] Cleaning up temporary files"
for ip in $live_hosts; do
    if [[ $ip =~ ^10\. ]]; then
        targetdir="$output_dir/ad_set/$ip"
    else
        targetdir="$output_dir/$ip"
    fi
    rm -f "$targetdir/temp_ports.txt"
done

if $was_set; then
    echo "[+] Globally set targets variable using “source ~/.zshrc”"
fi
echo "[+] Reconnaissance complete"
