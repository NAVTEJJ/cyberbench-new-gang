FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ app/
COPY wsgi.py .
RUN mkdir -p /app/data
ENV ORCHESTRATOR_URL=http://orchestrator:8100
ENV APPROVAL_URL=http://approval:8300
EXPOSE 5000
CMD ["gunicorn","--bind","0.0.0.0:5000","--workers","1","--timeout","60","wsgi:application"]
