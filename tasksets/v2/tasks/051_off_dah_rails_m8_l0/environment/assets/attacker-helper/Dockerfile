FROM python:3.12-slim

WORKDIR /app

RUN python -m pip install --no-cache-dir Flask==3.0.3 mysql-connector-python==9.0.0

COPY server.py /app/server.py

CMD ["python", "/app/server.py"]
