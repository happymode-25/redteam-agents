# Toolchain image: pinned external scanners for safety.runner: docker
# Build: docker build -t redteam-toolchain:latest docker/
# Adjust version ARGs to pins you have reviewed — do not track :latest.
FROM ubuntu:24.04

ARG GO_VERSION=1.27.2
ARG NUCLEI_VERSION=v3.3.7
ARG HTTPX_VERSION=v1.6.10
ARG SUBFINDER_VERSION=v2.6.7
ARG KATANA_VERSION=v1.8.0
ARG FFUF_VERSION=v2.3.0

RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap ca-certificates curl git gcc g++ \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" | tar -C /usr/local -xz
ENV PATH=/usr/local/go/bin:/root/go/bin:$PATH

RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION} \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION} \
    && go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION} \
    && go install -v github.com/projectdiscovery/katana/cmd/katana@${KATANA_VERSION} \
    && go install -v github.com/ffuf/ffuf/v2/cmd/ffuf@${FFUF_VERSION} \
    && rm -rf /root/go/pkg /root/.cache/go-build

# Build toolchain is no longer needed at runtime (katana wants a C compiler
# only while building); drop it and the Go SDK to keep the image lean.
RUN apt-get purge -y gcc g++ && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* /usr/local/go

# Containers run with --cap-drop ALL; nmap defaults to connect scans (-Pn is set by the tool)
USER nobody
