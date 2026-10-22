# Companion agent image. Multi-stage: build the Go recon tools, then a slim
# Node runtime that also has nmap. Base images are multi-arch, so this builds
# natively on Apple Silicon (arm64) with no emulation.

# ---- stage 1: fetch Go-based ProjectDiscovery tools -------------------------
FROM golang:1.25-bookworm AS tools
# GOTOOLCHAIN=auto lets `go install` fetch a newer Go automatically if a tool
# requires one — so we don't have to bump this base image every time a tool
# raises its minimum Go version.
ENV GOBIN=/out GOTOOLCHAIN=auto
RUN mkdir -p /out && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/hahwul/dalfox/v2@latest
# Phase 1 Go tools (non-fatal individually so one bad module path can't fail the image).
RUN go install github.com/tomnomnom/assetfinder@latest || true; \
    go install github.com/projectdiscovery/cvemap/cmd/cvemap@latest || true; \
    go install github.com/owasp-amass/amass/v4/...@master || true; \
    go install github.com/d3mondev/puredns/v2@latest || true; \
    go install github.com/PentestPad/subzy@latest || true; \
    go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest || true; \
    go install github.com/sensepost/gowitness@latest || true; \
    go install github.com/zricethezav/gitleaks/v8@latest || true

# ---- stage 2: runtime -------------------------------------------------------
FROM node:20-bookworm-slim

# nmap + libpcap (naabu) + CA certs (TLS) + curl/tar/unzip. feroxbuster's arm64
# release asset is a .zip, so unzip is required for the installer to extract it.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      nmap libpcap0.8 ca-certificates curl tar unzip sqlmap \
      git make gcc python3 python3-venv pipx ruby ruby-dev build-essential chromium && \
    rm -rf /var/lib/apt/lists/*

COPY --from=tools /out/ /usr/local/bin/

# --- Phase 1: Python tools via pipx (isolated); non-fatal each ---------------
ENV PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin PATH=/usr/local/bin:$PATH
RUN pipx install arjun || true; \
    pipx install s3scanner || true; \
    pipx install wafw00f || true; \
    pipx install commix || true
# trufflehog: prebuilt binary (its go module needs Go 1.26); non-fatal.
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin || true
# SSTImap: not on PyPI — clone + shim onto PATH (like jwt_tool).
RUN git clone --depth 1 https://github.com/vladko312/SSTImap /opt/sstimap 2>/dev/null && \
    pip3 install --break-system-packages -r /opt/sstimap/requirements.txt 2>/dev/null; \
    printf '#!/bin/sh\nexec python3 /opt/sstimap/sstimap.py "$@"\n' > /usr/local/bin/sstimap && \
    chmod +x /usr/local/bin/sstimap || true
# jwt_tool ships as a script (no pip package): clone + shim onto PATH.
RUN git clone --depth 1 https://github.com/ticarpi/jwt_tool /opt/jwt_tool 2>/dev/null && \
    pip3 install --break-system-packages -r /opt/jwt_tool/requirements.txt 2>/dev/null; \
    printf '#!/bin/sh\nexec python3 /opt/jwt_tool/jwt_tool.py "$@"\n' > /usr/local/bin/jwt_tool && \
    chmod +x /usr/local/bin/jwt_tool || true

# --- WordPress scanner (Ruby gem; needs ruby-dev + build tools) --------------
RUN gem install --no-document wpscan || true

# --- massdns (C; puredns depends on it) + a small trusted resolver list ------
RUN git clone --depth 1 https://github.com/blechschmidt/massdns /opt/massdns 2>/dev/null && \
    make -C /opt/massdns 2>/dev/null && cp /opt/massdns/bin/massdns /usr/local/bin/ 2>/dev/null; \
    printf '1.1.1.1\n8.8.8.8\n9.9.9.9\n8.8.4.4\n1.0.0.1\n' > /resolvers.txt || true

# --- SecLists subset (Discovery/DNS + Web-Content) for ffuf/feroxbuster/puredns
RUN git clone --depth 1 --filter=blob:none --sparse https://github.com/danielmiessler/SecLists /usr/share/seclists 2>/dev/null && \
    git -C /usr/share/seclists sparse-checkout set Discovery/DNS Discovery/Web-Content 2>/dev/null || true

# feroxbuster (Rust; not a `go install`) via its multi-arch installer. Non-fatal
# if the download fails offline — /health will just show it unavailable.
RUN curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash -s /usr/local/bin || true

# A small content-discovery wordlist for ffuf/feroxbuster (AGENT_WORDLIST default).
RUN mkdir -p /usr/share/wordlists/dirb && \
    curl -sL https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt \
      -o /usr/share/wordlists/dirb/common.txt || true

# Pre-fetch nuclei templates so the first scan isn't slow (non-fatal if offline).
RUN nuclei -update-templates >/dev/null 2>&1 || true

WORKDIR /app
COPY . .

# In-container the process must bind 0.0.0.0 to be reachable via the published
# port; the compose file restricts host exposure to 127.0.0.1.
ENV AGENT_BIND=0.0.0.0 AGENT_PORT=8787
EXPOSE 8787

CMD ["node", "server.js"]
