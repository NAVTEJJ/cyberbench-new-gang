FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
      --trusted-host pypi.org \
      --trusted-host files.pythonhosted.org \
      "flask>=3.0"

COPY app.py /app/app.py

RUN mkdir -p /app /logs/agent /logs/verifier /tests

WORKDIR /app
EXPOSE 5000
CMD ["python", "/app/app.py"]
