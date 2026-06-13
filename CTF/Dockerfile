FROM python:3.12-slim

WORKDIR /app

COPY service ./service

RUN useradd --create-home --shell /usr/sbin/nologin appuser \
    && mkdir -p /app/service/data \
    && chown -R appuser:appuser /app

USER appuser

ENV PORT=8080
ENV LEDGER_DATA=/app/service/data
ENV PYTHONUNBUFFERED=1

EXPOSE 8080

CMD ["python", "service/app.py"]
