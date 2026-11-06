FROM docker.io/library/python:3.12-slim-trixie

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd --system --uid 10001 --create-home app
WORKDIR /app

# Refresh the Debian 13 runtime packages in the base layer before adding Python
# dependencies. Keep pip current and install only the application runtime packages.
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir \
       openobserve-telemetry-sdk \
       PyYAML

COPY security-ai/ /app/security-ai/
COPY ansible-ai/ /app/ansible-ai/

RUN mkdir -p /state && chown -R app:app /app /state

USER 10001:10001
ENTRYPOINT ["python"]
