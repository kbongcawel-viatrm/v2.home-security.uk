FROM docker.io/library/python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd --system --uid 10001 --create-home app
WORKDIR /app

# Keep dependency installation in its own layer so application source changes
# do not invalidate the expensive pip install layer.
RUN python -m pip install --no-cache-dir \
    openobserve-telemetry-sdk \
    PyYAML

COPY security-ai/ /app/security-ai/
COPY ansible-ai/ /app/ansible-ai/

RUN mkdir -p /state && chown -R app:app /app /state

USER 10001:10001
ENTRYPOINT ["python"]
