FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir .

ENV CURATOR_SKILL_REGISTRY_HOME=/data
VOLUME ["/data"]
EXPOSE 8082

# The signing key must exist in /data before serving; generate it once with
# `curator-skill-registry --home /data genkey` in a mounted volume.
CMD ["curator-skill-registry", "--home", "/data", "serve", "--host", "0.0.0.0", "--port", "8082"]
