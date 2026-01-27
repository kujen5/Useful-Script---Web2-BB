#!/bin/bash

# 1. Check for Go, install if missing
if command -v go >/dev/null; then
    echo "Go is already installed: $(go version)"
else
    echo "Go not installed. Installing Go 1.24.12..."
    
    # Download Go 1.24.12 specifically
    # We use -f to fail silently on server errors so tar doesn't try to unzip an error page
    if curl -fsSL https://go.dev/dl/go1.24.12.linux-amd64.tar.gz -o go.tar.gz; then
        # Remove old installation if it exists
        sudo rm -rf /usr/local/go
        
        # Extract to /usr/local
        sudo tar -C /usr/local -xzf go.tar.gz
        rm go.tar.gz
        
        # Setup Path for CURRENT session so the rest of the script works
        export PATH=$PATH:/usr/local/go/bin
        
        # Setup Path for FUTURE sessions (persist to bashrc)
        if ! grep -q '/usr/local/go/bin' ~/.bashrc; then
            echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
        fi
        
        echo "Go $(go version) installed successfully"
    else
        echo "Failed to download Go! Check your internet connection or the version number."
        exit 1
    fi
fi

# 2. Installing recon tools
echo "Checking / installing core recon tools..."

# Define tools list
for tool in \
    "subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" \
    "httpx     github.com/projectdiscovery/httpx/cmd/httpx@latest" \
    "nuclei    github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" \
    "ffuf      github.com/ffuf/ffuf/v2@latest"; do

    name=$(echo $tool | awk '{print $1}')
    repo=$(echo $tool | awk '{print $2}')

    # Check if tool exists
    if command -v "$name" >/dev/null 2>&1; then
        echo "→ $name already installed"
        # Try standard version flags, suppress massive help output if they fail
        $name -version 2>/dev/null || $name -V 2>/dev/null || echo "    (Version check skipped to avoid spam)"
    else
        echo "→ Installing $name ..."
        # Run go install
        if go install -v "$repo"; then
            echo "    → $name installed successfully"
            # Add GOPATH/bin to PATH for this session just in case
            export PATH=$PATH:$(go env GOPATH)/bin
        else
            echo "    → Installation failed!"
        fi
    fi
done

# 3. Update nuclei templates if installed
if command -v nuclei >/dev/null; then
    echo "Updating Nuclei templates..."
    nuclei -update-templates 2>/dev/null
fi
