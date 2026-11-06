ARG FLUENT_BIT_BASE_IMAGE=cr.fluentbit.io/fluent/fluent-bit:5.1.5-debug

FROM ${FLUENT_BIT_BASE_IMAGE}

# The standard Fluent Bit image is distroless and cannot install Debian security
# updates. The debug variant supplies Debian's package manager; keep Fluent Bit's
# normal executable entrypoint so Compose's configured command remains valid.
USER root
RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/fluent-bit/bin/fluent-bit"]