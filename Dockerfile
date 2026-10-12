ARG SOURCE_DATE_EPOCH=0
FROM python:3.11.17-slim-trixie@sha256:e88e9763f943ec1834f992a4b51e0f24500486803e8bc534e5767af9ea65f6ce AS builder

ARG SOURCE_DATE_EPOCH=0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install --upgrade pip==25.1.1 setuptools==80.9.0 wheel==0.46.2 \
    && python -m pip wheel --no-cache-dir --wheel-dir /wheels .

FROM python:3.11.17-slim-trixie@sha256:e88e9763f943ec1834f992a4b51e0f24500486803e8bc534e5767af9ea65f6ce AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH="/home/appuser/.local/bin:${PATH}"

ARG APP_VERSION=0.1.0
ARG VCS_REF=unknown
ARG BUILD_TIMESTAMP=unknown
ARG SOURCE_DATE_EPOCH=0

RUN addgroup --system --gid 10001 appuser \
    && adduser --system --uid 10001 --ingroup appuser --home /home/appuser appuser

WORKDIR /app
COPY --from=builder /wheels /wheels
RUN python -m pip install --no-cache-dir --no-index --find-links=/wheels genomic-research-access-api==${APP_VERSION} \
    && python -m pip uninstall -y pip setuptools wheel \
    && rm -rf /wheels /root/.cache/pip

LABEL org.opencontainers.image.title="Genomic Research Access API" \
    org.opencontainers.image.version="${APP_VERSION}" \
    org.opencontainers.image.revision="${VCS_REF}" \
    org.opencontainers.image.created="${BUILD_TIMESTAMP}" \
    org.opencontainers.image.source="https://github.com/Ibraheemolasupogit/devsecops-application-security-pipeline"

USER appuser
EXPOSE 8000
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).read()"

CMD ["uvicorn", "genomic_research_access_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
