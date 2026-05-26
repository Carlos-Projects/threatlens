FROM python:3.11-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src/ src/
RUN pip install --no-cache-dir hatch && \
    pip install --no-cache-dir -e . && \
    pip install --no-cache-dir uvicorn python-multipart

FROM python:3.11-slim AS runner

WORKDIR /app
COPY --from=builder /usr/local/lib/python3.11/site-packages/ /usr/local/lib/python3.11/site-packages/
COPY --from=builder /usr/local/bin/ /usr/local/bin/
COPY --from=builder /build/src/ src/

ENV THREATLENS_DB_PATH=/data/threatlens.db
ENV THREATLENS_CONFIG=/data/config.yaml

VOLUME ["/data"]
EXPOSE 8080

ENTRYPOINT ["threatlens"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
