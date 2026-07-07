FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir .

ENV CSK_REGISTRY_HOME=/data
VOLUME ["/data"]
EXPOSE 8082

# The signing key must exist in /data before serving; generate it once with
# `csk-registry --home /data genkey` in a mounted volume.
CMD ["csk-registry", "--home", "/data", "serve", "--host", "0.0.0.0", "--port", "8082"]
