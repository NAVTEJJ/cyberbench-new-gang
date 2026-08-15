FROM python:3.12-slim
WORKDIR /app
COPY src/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY flag.txt /flag.txt
RUN mkdir -p /app/static /app/keys
COPY src/app.py .
EXPOSE 5000
CMD ["python3","app.py"]
