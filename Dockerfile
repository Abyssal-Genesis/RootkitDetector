# RootkitDetector — Dockerfile
# Linux rootkit detection using LKM + userspace analysis
FROM python:3.12-slim-bookworm

LABEL maintainer="morningstar"
LABEL org.opencontainers.image.title="RootkitDetector"

ARG UID=1000 GID=1000

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential linux-headers-amd64 \
    python3-pip git curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u $UID -g $GID -s /bin/bash analyst \
    && mkdir -p /workspace /home/analyst/.config \
    && chown -R $UID:$GID /workspace

WORKDIR /workspace
COPY --chown=$UID:$GID RootkitDetector/ /workspace/RootkitDetector/

USER analyst
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/workspace/RootkitDetector

CMD ["python3", "-c", "print('RootkitDetector ready. Run: python3 rootkit_detector.py --help')"]
