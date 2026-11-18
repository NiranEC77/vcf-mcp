FROM python:3.12-slim

RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin app
WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY specs ./specs
RUN pip install --no-cache-dir ".[http]"

USER 1000
ENV PORT=8080 \
    HOST=0.0.0.0 \
    PYTHONUNBUFFERED=1
EXPOSE 8080
CMD ["vcf-mcp"]
