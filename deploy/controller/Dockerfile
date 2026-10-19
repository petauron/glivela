# Packages the already verified, immutable release bundle. No shell, package
# manager, host socket or systemd runs in the controller image.
FROM scratch
ARG TARGETARCH
ARG GLIVELA_VERSION
ARG GLIVELA_COMMIT
LABEL org.opencontainers.image.title="Glivela" \
      org.opencontainers.image.source="https://github.com/petauron/glivela" \
      org.opencontainers.image.version="${GLIVELA_VERSION}" \
      org.opencontainers.image.revision="${GLIVELA_COMMIT}"
COPY ${TARGETARCH}/ /opt/glivela/
COPY --chown=65532:65532 --chmod=0700 state/ /var/lib/glivela/
USER 65532:65532
ENTRYPOINT ["/opt/glivela/glivela"]

