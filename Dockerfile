FROM python:3.12-slim@sha256:dd29372629eeba2dd003fd9e9d35a5b8236c44727875a0364254b5127af88e65 AS builder
COPY --from=ghcr.io/astral-sh/uv:0.12.4@sha256:d0a6eca6c669dc7e9c51218707b8438a3d30402733d739dcc00adb3e213e8f5c /uv /bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project
COPY . .
RUN uv sync --frozen

FROM python:3.12-slim@sha256:dd29372629eeba2dd003fd9e9d35a5b8236c44727875a0364254b5127af88e65
WORKDIR /app
RUN groupadd -g 10001 appuser && useradd -M -u 10001 -g appuser appuser
COPY --from=builder --chown=10001:10001 /app /app
RUN chown 10001:10001 /app
USER 10001
EXPOSE 8080
CMD ["/app/.venv/bin/chainlit", "run", "app.py", "--host", "0.0.0.0", "--port", "8080"]
