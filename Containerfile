ARG PYTHON_IMAGE=docker.io/library/python:3.13-slim-trixie@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91

FROM ${PYTHON_IMAGE} AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN python -m venv /opt/venv

COPY pyproject.toml README.md /build/
COPY src /build/src

RUN /opt/venv/bin/pip install --no-cache-dir /build \
    && /opt/venv/bin/python -c "from kyn.main import create_app; from kyn.provision import provision"

FROM ${PYTHON_IMAGE}

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 10010 kyn \
    && useradd --create-home --uid 10010 --gid 10010 --shell /usr/sbin/nologin kyn

COPY --from=builder /opt/venv /opt/venv
COPY migrations /app/migrations

RUN find /app -type d -exec chmod 0555 {} + \
    && find /app -type f -exec chmod 0444 {} +

USER 10010:10010
WORKDIR /app

EXPOSE 8090

CMD ["kyn-api"]
