ARG OPENOBSERVE_BASE_IMAGE=public.ecr.aws/zinclabs/openobserve:latest

FROM ${OPENOBSERVE_BASE_IMAGE} AS openobserve

FROM docker.io/library/python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=openobserve /openobserve /openobserve

RUN ["/openobserve", "init-dir", "-p", "/data/"]

ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
VOLUME ["/data"]
EXPOSE 5080
CMD ["/openobserve"]