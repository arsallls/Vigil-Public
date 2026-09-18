FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends git openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir semgrep

WORKDIR /app
COPY scan.py report.py server.py rules.yaml ./

# This process reads hostile diffs. It does not need root.
RUN useradd -m -u 10001 dg && chown -R dg /app
USER dg

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s \
  CMD python3 -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/healthz')"
CMD ["python3", "server.py"]
