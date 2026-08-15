FROM python:3.12-slim

WORKDIR /app
COPY src/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/app.py .
COPY flag.txt /flag.txt

ENV FLASK_APP=app.py

EXPOSE 5000
CMD ["python", "app.py"]
