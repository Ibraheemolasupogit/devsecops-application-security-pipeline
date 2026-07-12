FROM python:3.11.13-slim-trixie AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN apt-get update \
    && apt-get -y upgrade \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --upgrade pip==25.1.1 setuptools==80.9.0 wheel==0.46.2 \
    && python -m pip wheel --no-cache-dir --wheel-dir /wheels .

FROM python:3.11.13-slim-trixie AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/home/appuser/.local/bin:${PATH}"

RUN addgroup --system appuser \
    && adduser --system --ingroup appuser --home /home/appuser appuser

WORKDIR /app
COPY --from=builder /wheels /wheels
RUN apt-get update \
    && apt-get -y upgrade \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --no-cache-dir --no-index --find-links=/wheels genomic-research-access-api==0.1.0 \
    && python -m pip uninstall -y pip setuptools wheel \
    && rm -rf /wheels /root/.cache/pip

USER appuser
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).read()"

CMD ["uvicorn", "genomic_research_access_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
