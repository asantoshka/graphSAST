# ── GraphSAST Docker image ────────────────────────────────────────────────────
#
# Build:
#   docker build -t graphsast .
#
# Run (scan a local project):
#   docker run --rm -v /path/to/myapp:/workspace graphsast scan /workspace
#
# Run with Claude backend:
#   docker run --rm \
#     -e ANTHROPIC_API_KEY=sk-ant-... \
#     -e GRAPHSAST_LLM__BACKEND=claude \
#     -v /path/to/myapp:/workspace \
#     graphsast scan /workspace --llm
#
# Run with Ollama (host network):
#   docker run --rm --network host \
#     -v /path/to/myapp:/workspace \
#     graphsast scan /workspace --llm --llm-url http://localhost:11434
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# System deps needed to compile tree-sitter grammars
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        g++ \
        git \
    && rm -rf /var/lib/apt/lists/*

# Copy only what's needed to install Python deps first (layer cache)
COPY requirements.txt requirements-claude.txt ./
COPY pyproject.toml ./
COPY graphsast/ ./graphsast/
COPY code_review_graph/ ./code_review_graph/ 2>/dev/null || true

# Install into a prefix we'll copy to the final stage
RUN pip install --no-cache-dir --prefix=/install \
        -r requirements.txt \
        -r requirements-claude.txt \
    && pip install --no-cache-dir --prefix=/install --no-deps .


# ── Stage 2: Semgrep (separate because it pulls large deps) ──────────────────
FROM python:3.11-slim AS semgrep

RUN pip install --no-cache-dir --prefix=/semgrep semgrep


# ── Stage 3: final runtime image ─────────────────────────────────────────────
FROM python:3.11-slim

LABEL org.opencontainers.image.title="GraphSAST" \
      org.opencontainers.image.description="Security analysis tool: code graph + vulnerability DB + LLM" \
      org.opencontainers.image.source="https://github.com/your-org/graphsast"

# Runtime system deps only
RUN apt-get update && apt-get install -y --no-install-recommends \
        libgomp1 \
        git \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Copy Semgrep
COPY --from=semgrep /semgrep /usr/local

# Non-root user for safety
RUN useradd -m -u 1000 graphsast
USER graphsast

# Default DB directory inside the container (can be overridden via env)
ENV GRAPHSAST_PATHS__DB_SUBDIR=".graphsast"

WORKDIR /workspace

ENTRYPOINT ["graphsast"]
CMD ["--help"]
