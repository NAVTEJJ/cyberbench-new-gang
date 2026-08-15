FROM python:3.12-slim

WORKDIR /app

RUN mkdir -p /app/logs && \
    echo "$(date) INFO  DevBoard started" > /app/logs/app.log && \
    echo "$(date) INFO  Loaded 0 users" >> /app/logs/app.log

COPY src/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY flag.txt /flag.txt
COPY src/app.py .

EXPOSE 5000
CMD ["python", "app.py"]
