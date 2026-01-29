#!/bin/bash

# Usage: ./recon.sh example.com
DOMAIN=$1
WORDLIST="subdomains-top1million-110000.txt"
RESOLVERS="resolvers.txt"

# --- HELPER: Spinner for API tasks ---
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

# --- HELPER: Check for PV (Progress Bar Tool) ---
if ! command -v pv &> /dev/null; then
    echo "[!] 'pv' is not installed. Installing it for progress bars..."
    if [ -x "$(command -v apt)" ]; then sudo apt update && sudo apt install -y pv
    elif [ -x "$(command -v brew)" ]; then brew install pv
    else echo "Please install 'pv' manually to see progress bars."; exit 1; fi
fi

# 1. Validation
if [ -z "$DOMAIN" ]; then
    echo "Usage: ./recon.sh <domain>"
    exit 1
fi

# 2. Create Output Directory
if [ ! -d "$DOMAIN" ]; then
    echo "[+] Creating output directory: $DOMAIN/"
    mkdir -p "$DOMAIN"
fi

echo "=========================================="
echo " SETUP & CHECKS"
echo "=========================================="

# 3. Check for Go
if ! command -v go >/dev/null; then
    echo "Go not installed. Installing Go 1.24.0..."
    if curl -fsSL https://go.dev/dl/go1.24.0.linux-amd64.tar.gz -o go.tar.gz; then
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf go.tar.gz
        rm go.tar.gz
        export PATH=$PATH:/usr/local/go/bin
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    else
        echo "Failed to download Go."
        exit 1
    fi
fi

# 4. Check/Install MassDNS
if ! command -v massdns &> /dev/null; then
    echo "[+] MassDNS not found. Installing..."
    if [ -d "massdns" ]; then rm -rf massdns; fi
    git clone https://github.com/blechschmidt/massdns.git
    cd massdns
    make
    sudo make install
    cd ..
    rm -rf massdns
fi

# 5. Check/Install Go Tools
for tool in \
    "subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" \
    "httpx     github.com/projectdiscovery/httpx/cmd/httpx@latest" \
    "nuclei    github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" \
    "ffuf      github.com/ffuf/ffuf/v2@latest" \
    "puredns   github.com/d3mondev/puredns/v2@latest" \
    "alterx    github.com/projectdiscovery/alterx/cmd/alterx@latest" \
    "anew      github.com/tomnomnom/anew@latest"; do

    name=$(echo $tool | awk '{print $1}')
    repo=$(echo $tool | awk '{print $2}')

    if ! command -v "$name" &> /dev/null; then
        echo "→ Installing $name..."
        go install -v "$repo"
        export PATH=$PATH:$(go env GOPATH)/bin
    fi
done

# Ensure Path is set for this session
export PATH=$PATH:$(go env GOPATH)/bin

# 6. Check/Download Wordlist & Resolvers
if [ ! -f "$WORDLIST" ]; then
    echo "[+] Downloading wordlist..."
    wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt" -O "$WORDLIST"
fi

if [ ! -f "$RESOLVERS" ]; then
    echo "[+] Downloading resolvers..."
    wget -q https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -O resolvers.txt
fi

echo "=========================================="
echo " RUNNING RECON ON: $DOMAIN"
echo "=========================================="

# --- Phase 1: Passive Recon ---
echo "[+] 1. Starting Passive Discovery (Subfinder)..."
# Subfinder is API based, so we use a spinner instead of a % bar
subfinder -d "$DOMAIN" -all -silent -o "$DOMAIN/passive.txt" &
PID=$!
spinner $PID
wait $PID
echo " -> Done."

# --- Phase 2: Filter Alive (Resolution) ---
echo "[+] 2. Filtering alive subdomains..."
# Removed --quiet so PureDNS native bar shows
puredns resolve "$DOMAIN/passive.txt" -r "$RESOLVERS" --write "$DOMAIN/passive_resolved.txt" --rate-limit 300

# --- Phase 3a: Bruteforce ---
echo "[+] 3a. Bruteforcing hidden subdomains..."
# Removed --quiet so PureDNS native bar shows
puredns bruteforce "$WORDLIST" "$DOMAIN" -r "$RESOLVERS" --write "$DOMAIN/bruteforce.txt" --rate-limit 300

# --- Phase 3b: Permutations ---
echo "[+] 3b. Generating Permutations..."
if [ -f "$DOMAIN/passive_resolved.txt" ] || [ -f "$DOMAIN/bruteforce.txt" ]; then
    cat "$DOMAIN/passive_resolved.txt" "$DOMAIN/bruteforce.txt" 2>/dev/null | sort -u > "$DOMAIN/known_alive.txt"
    
    if [ -s "$DOMAIN/known_alive.txt" ]; then
        # Removed --quiet so PureDNS native bar shows
        cat "$DOMAIN/known_alive.txt" | alterx -silent | puredns resolve -r "$RESOLVERS" --write "$DOMAIN/permutations.txt" --rate-limit 300
    else
        touch "$DOMAIN/permutations.txt"
    fi
else
    touch "$DOMAIN/permutations.txt"
fi

# --- Merge All ---
echo "[+] Merging all subdomain lists..."
cat "$DOMAIN/passive_resolved.txt" "$DOMAIN/bruteforce.txt" "$DOMAIN/permutations.txt" 2>/dev/null | sort -u > "$DOMAIN/final_all.txt"
COUNT=$(wc -l < "$DOMAIN/final_all.txt")
echo "    -> Found $COUNT live subdomains."

# --- Phase 5: Web Probing ---
if [ "$COUNT" -gt 0 ]; then
    echo "[+] 5. Probing for Web Servers (HTTPX)..."
    
    # Using 'pv' to show a progress bar based on the line count ($COUNT)
    cat "$DOMAIN/final_all.txt" | \
    pv -N "Probing" -p -t -e -s "$COUNT" | \
    httpx \
          -title -status-code -ip -cname -tech-detect -web-server \
          -random-agent \
          -follow-redirects \
          -threads 50 \
          -o "$DOMAIN/web_assets.txt" -silent

    echo ""
    echo "    -> HTTP assets saved to: $DOMAIN/web_assets.txt"
else
    echo "[!] No subdomains found. Skipping HTTP probing."
fi

echo "=========================================="
echo " RECON FINISHED."
echo " Results saved in folder: $DOMAIN/"
echo "=========================================="