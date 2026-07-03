FROM python:3.12-slim

WORKDIR /app

# Non-root: the service holds no secrets beyond the internal token env and needs no
# filesystem writes at runtime.
RUN useradd --create-home --uid 1000 slimx

COPY pyproject.toml README.md ./
COPY slimx_mcp ./slimx_mcp
RUN pip install --no-cache-dir .

USER slimx

EXPOSE 8091

HEALTHCHECK --interval=15s --timeout=3s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8091/health', timeout=2)"

CMD ["uvicorn", "slimx_mcp.service:app", "--host", "0.0.0.0", "--port", "8091"]
