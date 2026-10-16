FROM docker.io/library/python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd --system --uid 10001 --create-home app
WORKDIR /app
RUN pip install --no-cache-dir ansible-core PyYAML
COPY worker.py ansible_agent.py ansible_knowledge.md \
     security_knowledge_base.py rule_generator.py /app/
RUN mkdir -p /state && chown -R app:app /app /state

USER 10001:10001
ENTRYPOINT ["python", "/app/worker.py"]
