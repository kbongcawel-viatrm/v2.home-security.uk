FROM docker.io/library/python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd --system --uid 10001 --create-home app
WORKDIR /app
COPY worker.py /app/worker.py
RUN mkdir -p /state && chown -R app:app /app /state

USER 10001:10001
ENTRYPOINT ["python", "/app/worker.py"]
