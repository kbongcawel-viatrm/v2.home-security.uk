FROM docker.io/library/python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd --system --uid 10001 --create-home app && \
    python -m pip install --no-cache-dir PyYAML

WORKDIR /app

COPY security-ai/worker.py \
     security-ai/artifact_writer.py \
     security-ai/source_catalog.py \
     security-ai/session_forensics_skill.md \
     /app/security-ai/
COPY ansible-ai/worker.py \
     ansible-ai/playbook_generator.py \
     /app/ansible-ai/

RUN mkdir -p /state && chown -R app:app /app /state

USER 10001:10001
ENTRYPOINT ["python"]