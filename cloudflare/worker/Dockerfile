# Sandbox container image for the sbom-scorer Worker.
#
# Build context is the repo root (see wrangler.jsonc's image_build_context),
# so this can COPY the existing Python package straight in — no rewrite of
# the scoring logic, CLI, or dimension modules.
FROM docker.io/cloudflare/sandbox:0.12.4

WORKDIR /workspace/app

COPY sbom_scorer ./sbom_scorer
COPY pyproject.toml weights.yaml README.md ./

# Debian-based images from 12+ mark the system Python as "externally
# managed" (PEP 668); fall back to --break-system-packages if the plain
# install is rejected, rather than fighting a venv inside the sandbox.
RUN python3 -m pip install --no-cache-dir -e . \
	|| python3 -m pip install --no-cache-dir --break-system-packages -e .

EXPOSE 8080
