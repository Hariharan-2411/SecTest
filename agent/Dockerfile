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
    go install github.com/tomnomnom/waybackurls@latest

# ---- stage 2: runtime -------------------------------------------------------
FROM node:20-bookworm-slim

# nmap + libpcap (naabu) + CA certs (TLS) + curl/tar/unzip. feroxbuster's arm64
# release asset is a .zip, so unzip is required for the installer to extract it.
RUN apt-get update && \
    apt-get install -y --no-install-recommends nmap libpcap0.8 ca-certificates curl tar unzip && \
    rm -rf /var/lib/apt/lists/*

COPY --from=tools /out/ /usr/local/bin/

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
