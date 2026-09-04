FROM python:3.12.11-alpine3.22@sha256:efcdfa6a6b2fd2afb9c7dfa9a5b288a6f68338b5cfdebe6b637d986067d85757

LABEL org.opencontainers.image.source="https://github.com/elder-plinius/T3MP3ST"
LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later"

WORKDIR /challenge
COPY --chown=65532:65532 challenge.py server.py proxy.py callback.py solve.py ./

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["python", "server.py"]
