FROM docker.io/library/python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && useradd --system --uid 10001 --no-create-home validator


COPY app ./app
COPY tests ./tests

USER validator
EXPOSE 8080 1344
# Concurrency and keep-alive are capped; request size is enforced by the app.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", \
     "--limit-concurrency", "32", "--timeout-keep-alive", "5", "--no-server-header", "--no-date-header"]
