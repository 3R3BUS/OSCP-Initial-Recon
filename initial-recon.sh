#!/bin/bash

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

# Check if targets is set
echo "[+] Checking for targets input"
was_set=false
if [ -z "$targets" ]; then
    if [ $# -eq 0 ]; then
        echo "Usage: ./startup.sh <targets> OR set \$targets variable"
        exit 1
    fi
    targets=$1
    setvar targets "$targets"
    was_set=true
fi

# Handle IP range or CIDR for ping sweep
echo "[+] Performing ping sweep on $targets"
if [[ $targets =~ [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+-[0-9]+ ]]; then
    # Convert range to list of IPs and store in a temporary file
    expand_ip_range "$targets" > temp_ips.txt
    fping -a -f temp_ips.txt 2>/dev/null > ping_sweep.txt
    rm temp_ips.txt
else
    # Assume CIDR or single IP
    fping -a -g "$targets" 2>/dev/null > ping_sweep.txt
fi

# Extract live hosts directly from ping_sweep.txt
echo "[+] Extracting live hosts"
live_hosts=$(cat ping_sweep.txt)
if [ -z "$live_hosts" ]; then
    echo "[-] No live hosts detected in $targets."
    exit 1
fi
echo "[+] Live hosts found: $live_hosts"

# Create ad_set directory and files
echo "[+] Creating ad_set directory and files"
mkdir -p ad_set
touch ad_set/usernames ad_set/passwords ad_set/credentials

# Create directories for each live host
echo "[+] Creating directories for live hosts"
first=true
for ip in $live_hosts; do
    mkdir -p "$ip"
    touch "$ip/usernames" "$ip/passwords" "$ip/credentials"
    if $first; then
        mv "$ip" ad_set/
        first=false
    fi
done

# Perform port scans in parallel
echo "[+] Starting port scans"
pids=()
for ip in $live_hosts; do
    if [ -d "ad_set/$ip" ]; then
        targetdir="ad_set/$ip"
    else
        targetdir="$ip"
    fi
    echo "[+] Scanning $ip (fast TCP, UDP, full TCP)"
    nmap -T4 "$ip" --top-ports 100 -oN "$targetdir/nmap_fast.txt" &
    pids+=($!)
    nmap -sU -T4 -p 161 -oN "$targetdir/nmap_udp.txt" --open &
    pids+=($!)
    nmap -sS -p- -T4 -v -oN "$targetdir/nmap_syn.txt" &
    pids+=($!)
done

# Wait for port scans to complete
echo "[+] Waiting for port scans to complete"
for pid in "${pids[@]}"; do
    wait "$pid"
done

# Extract open ports for each target (for later scans)
echo "[+] Extracting open ports for version and vulnerability scans"
for ip in $live_hosts; do
    if [ -d "ad_set/$ip" ]; then
        targetdir="ad_set/$ip"
    else
        targetdir="$ip"
    fi
    ports=$( (grep "/tcp.*open" "$targetdir/nmap_syn.txt" | awk '{print $1}' | cut -d/ -f1; grep "/udp.*open" "$targetdir/nmap_udp.txt" | awk '{print $1}' | cut -d/ -f1) | sort -nu | tr '\n' ',' | sed 's/,$//')
    echo "$ports" > "$targetdir/temp_ports.txt"
done

# Version scanning with XML output and searchsploit
echo "[+] Starting version scanning"
pids=()
for ip in $live_hosts; do
    if [ -d "ad_set/$ip" ]; then
        targetdir="ad_set/$ip"
    else
        targetdir="$ip"
    fi
    ports=$(cat "$targetdir/temp_ports.txt")
    if [ -n "$ports" ]; then
        echo "[+] Version scanning $ip on ports $ports"
        nmap -sV -p "$ports" "$ip" -oN "$targetdir/nmap_version.txt" -oX "$targetdir/nmap_version.xml" &
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
for ip in $live_hosts; do
    if [ -d "ad_set/$ip" ]; then
        targetdir="ad_set/$ip"
    else
        targetdir="$ip"
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

# Vulnerability scanning
echo "[+] Starting vulnerability scanning"
pids=()
for ip in $live_hosts; do
    if [ -d "ad_set/$ip" ]; then
        targetdir="ad_set/$ip"
    else
        targetdir="$ip"
    fi
    ports=$(cat "$targetdir/temp_ports.txt")
    if [ -n "$ports" ]; then
        echo "[+] Vulnerability scanning $ip on ports $ports"
        nmap -sV --script=vuln -p "$ports" "$ip" -oN "$targetdir/nmap_vuln.txt" &
        pids+=($!)
    fi
done

# Wait for vuln scans
echo "[+] Waiting for vulnerability scans to complete"
for pid in "${pids[@]}"; do
    wait "$pid"
done

# Run enum4linux-ng for all hosts in parallel with RID brute-forcing
echo "[+] Starting enum4linux-ng enumeration with RID brute-forcing"
pids=()
for ip in $live_hosts; do
    if [ -d "ad_set/$ip" ]; then
        targetdir="ad_set/$ip"
    else
        targetdir="$ip"
    fi
    echo "[+] Running enum4linux-ng on $ip with RID brute-forcing (500-1000)"
    enum4linux-ng -d -A -O -R 500-1000 "$ip" > "$targetdir/enum4.txt" &
    pids+=($!)
done

# Wait for enum4linux-ng to complete
echo "[+] Waiting for enum4linux-ng to complete"
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
        nmap -n -sV -Pn -p"$port" --script=ftp* -oN "$targetdir/${ip}_ftp_${port}.nmap" "$ip" &
        pids+=($!)
        hydra -L /usr/share/seclists/Usernames/Names/names.txt -P /usr/share/wordlists/rockyou.txt -f -o "$targetdir/${ip}_ftphydra" -u "$ip" -s "$port" ftp &
        pids+=($!)
    elif [[ "$serv" == "http" || "$serv" == "http?" ]]; then
        nmap -n -sV -Pn -p"$port" --script=http-brute,http-svn-enum,http-svn-info,http-git,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-iis-webdav-vuln,http-vuln-cve2009-3960,http-vuln-cve2010-0738,http-vuln-cve2011-3368,http-vuln-cve2012-1823,http-vuln-cve2013-0156,http-waf-detect,http-waf-fingerprint,ssl-enum-ciphers,ssl-known-key -oN "$targetdir/${ip}_http_${port}.nmap" "$ip" &
        pids+=($!)
        nmap -n -sV -Pn -p"$port" --script=http-shellshock-spider -oN "$targetdir/${ip}_http_shellshock_${port}.nmap" "$ip" &
        pids+=($!)
        nikto -h "$ip" -p "$port" | tee "$targetdir/${ip}_nikto_${port}" &
        pids+=($!)
        whatweb --color=never --no-errors "http://$ip:$port" | tee "$targetdir/${ip}_whatweb_${port}" &
        pids+=($!)
        # Run wpscan anyway, as in original script
        wpscan --url "http://$ip:$port" -e ap,vt,cb,u | tee "$targetdir/${ip}_wpscan_${port}" &
        pids+=($!)
        wpscan --url "http://$ip:$port" -P /usr/share/wordlists/rockyou.txt -U admin | tee "$targetdir/${ip}_wpscan_brute_${port}" &
        pids+=($!)
        # Use feroxbuster instead of gobuster for directory enumeration
        feroxbuster --url "http://$ip:$port" -w /usr/share/wordlists/dirb/common.txt --extract-links --scan-limit 1 | tee "$targetdir/${ip}_ferox_common_${port}" &
        pids+=($!)
        feroxbuster --url "http://$ip:$port" -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt --extract-links --scan-limit 1 | tee "$targetdir/${ip}_ferox_medium_${port}" &
        pids+=($!)
        medusa -U /usr/share/wordlists/metasploit/http_default_users.txt -P /usr/share/wordlists/rockyou.txt -e ns -h "$ip" -p "$port" -M http -m DIR:secret -f &
        pids+=($!)
    elif [[ "$serv" == "ssl/http" || "$serv" == *"https"* ]]; then
        nmap -n -sV -Pn -p"$port" --script=http-brute,http-svn-enum,http-svn-info,http-git,ssl-heartbleed,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-iis-webdav-vuln,http-vuln-cve2009-3960,http-vuln-cve2010-0738,http-vuln-cve2011-3368,http-vuln-cve2012-1823,http-vuln-cve2013-0156,http-waf-detect,http-waf-fingerprint,ssl-enum-ciphers,ssl-known-key -oN "$targetdir/${ip}_https_${port}.nmap" "$ip" &
        pids+=($!)
        nmap -n -sV -Pn -p"$port" --script=http-shellshock-spider -oN "$targetdir/${ip}_http_shellshock_${port}.nmap" "$ip" &
        pids+=($!)
        nikto -h "$ip" -p "$port" | tee "$targetdir/${ip}_nikto_https_${port}.txt" &
        pids+=($!)
        whatweb --color=never --no-errors "https://$ip:$port" | tee "$targetdir/${ip}_whatweb_https_${port}" &
        pids+=($!)
        wpscan --url "https://$ip:$port" -e ap,vt,cb,u | tee "$targetdir/${ip}_wpscan_https_${port}" &
        pids+=($!)
        wpscan --url "https://$ip:$port" -P /usr/share/wordlists/rockyou.txt -U admin | tee "$targetdir/${ip}_wpscan_https_brute_${port}" &
        pids+=($!)
        feroxbuster --url "https://$ip:$port" --insecure -w /usr/share/wordlists/dirb/common.txt --extract-links --scan-limit 1 | tee "$targetdir/${ip}_ferox_https_common_${port}" &
        pids+=($!)
        feroxbuster --url "https://$ip:$port" --insecure -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt --extract-links --scan-limit 1 | tee "$targetdir/${ip}_ferox_https_medium_${port}" &
        pids+=($!)
        medusa -U /usr/share/wordlists/metasploit/http_default_users.txt -P /usr/share/wordlists/rockyou.txt -e ns -h "$ip" -p "$port" -M http -m DIR:secret -f &
        pids+=($!)
    elif [[ "$serv" == *"cassandra"* ]]; then
        nmap -n -sV -Pn -p "$port" --script=cassandra* -oN "$targetdir/${ip}_cassandra_${port}.nmap" "$ip" &
        pids+=($!)
    elif [[ "$serv" == *"mongodb"* ]]; then
        nmap -n -sV -Pn -p "$port" --script=mongodb* -oN "$targetdir/${ip}_mongodb_${port}.nmap" "$ip" &
        pids+=($!)
    elif [[ "$serv" == *"oracle"* ]]; then
        nmap -n -sV -Pn -p "$port" --script=oracle* -oN "$targetdir/${ip}_oracle_${port}.nmap" "$ip" &
        pids+=($!)
    elif [[ "$serv" == *"mysql"* ]]; then
        nmap -n -sV -Pn -p "$port" --script=mysql* -oN "$targetdir/${ip}_mysql_${port}.nmap" "$ip" &
        pids+=($!)
    elif [[ "$serv" == *"ms-sql"* ]]; then
        nmap -n -sV -Pn -p"$port" --script=ms-sql-ntlm-info,ms-sql-brute,ms-sql-empty-password,ms-sql-info,ms-sql-config,ms-sql-dump-hashes -oN "$targetdir/${ip}_mssql_${port}.nmap" "$ip" &
        pids+=($!)
    elif [[ "$serv" == *"microsoft-ds"* || "$serv" == *"netbios-ssn"* ]]; then
        nmap -n -sV -Pn -pT:139,"$port",U:137 --script=smb-enum-shares,smb-enum-domains,smb-enum-groups,smb-enum-processes,smb-enum-sessions,smb-ls,smb-mbenum,smb-os-discovery,smb-print-text,smb-security-mode,smb-server-stats,smb-system-info,smb-vuln* -oN "$targetdir/${ip}_smb_${port}.nmap" "$ip" &
        pids+=($!)
        smbclient -L \\ -N -I "$ip" | tee "$targetdir/${ip}_smbclient" &
        pids+=($!)
        smbmap -u guest -H "$ip" -R | tee "$targetdir/${ip}_smbmap" &
        pids+=($!)
    elif [[ "$serv" == *"ldap"* ]]; then
        nmap -n -sV -Pn -p"$port" --script=ldap-search.nse -oN "$targetdir/${ip}_ldap_${port}.nmap" "$ip" &
        pids+=($!)
        ldapsearch -H ldap://"$ip" -x -LLL -s base -b "" supportedSASLMechanisms | tee "$targetdir/${ip}_ldapsearch_${port}" &
        pids+=($!)
    elif [[ "$serv" == *"msdrdp"* || "$serv" == *"ms-wbt-server"* ]]; then
        ncrack -vv --user Administrator -P /usr/share/wordlists/rockyou.txt rdp://"$ip" &
        pids+=($!)
    elif [[ "$serv" == *"smtp"* ]]; then
        nmap -n -sV -Pn -p"$port" --script=smtp* -oN "$targetdir/${ip}_smtp_${port}.nmap" "$ip" &
        pids+=($!)
        smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t "$ip" -p "$port" | tee "$targetdir/${ip}_smtp_enum_${port}" &
        pids+=($!)
    elif [[ "$serv" == *"snmp"* || "$serv" == *"smux"* ]]; then
        nmap -n -sU -sV -Pn -pU:"$port" --script=snmp-sysdescr,snmp-info,snmp-netstat,snmp-processes -oN "$targetdir/${ip}_snmp_${port}.nmap" "$ip" &
        pids+=($!)
        onesixtyone -c public "$ip" | tee "$targetdir/${ip}_161" &
        pids+=($!)
        snmpwalk -c public -v1 "$ip" | tee "$targetdir/${ip}_snmpwalk" &
        pids+=($!)
        snmpwalk -c public -v1 "$ip" 1.3.6.1.4.1.77.1.2.25 | tee "$targetdir/${ip}_snmp_users" &
        pids+=($!)
        snmpwalk -c public -v1 "$ip" 1.3.6.1.2.1.6.13.1.3 | tee "$targetdir/${ip}_snmp_ports" &
        pids+=($!)
        snmpwalk -c public -v1 "$ip" 1.3.6.1.2.1.25.4.2.1.2 | tee "$targetdir/${ip}_snmp_process" &
        pids+=($!)
        snmpwalk -c public -v1 "$ip" 1.3.6.1.2.1.25.6.3.1.2 | tee "$targetdir/${ip}_snmp_software" &
        pids+=($!)
        snmpwalk -c public -v1 "$ip" NET-SNMP-EXTEND-MIB::nsExtendOutputFull | tee "$targetdir/${ip}_snmp_software" &
        pids+=($!)
    elif [[ "$serv" == *"ssh"* ]]; then
        medusa -u root -P /usr/share/wordlists/rockyou.txt -e ns -h "$ip" -p "$port" -M ssh -f &
        pids+=($!)
        medusa -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/rockyou.txt -e ns -h "$ip" -p "$port" -M ssh -f &
        pids+=($!)
        hydra -f -V -t 1 -l root -P /usr/share/wordlists/rockyou.txt -s "$port" "$ip" ssh &
        pids+=($!)
    elif [[ "$serv" == *"telnet"* ]]; then
        medusa -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/rockyou.txt -e ns -h "$ip" -p "$port" -M telnet -t1 -f &
        pids+=($!)
    elif [[ "$serv" == *"domain"* ]]; then
        nmap -n -sV -Pn -p"$port" --script=dns* -oN "$targetdir/${ip}_dns_${port}.nmap" "$ip" &
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
    if [ -d "ad_set/$ip" ]; then
        targetdir="ad_set/$ip"
    else
        targetdir="$ip"
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
    if [ -d "ad_set/$ip" ]; then
        targetdir="ad_set/$ip"
    else
        targetdir="$ip"
    fi
    rm -f "$targetdir/temp_ports.txt"
done

if $was_set; then
    echo "[+] Globally set targets variable using “source ~/.zshrc”"
fi
echo "[+] Reconnaissance complete"