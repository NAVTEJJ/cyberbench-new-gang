FROM python:3.12-slim

WORKDIR /app
COPY app.py aes.py aes_cbc.py flag.txt ./

EXPOSE 5000
CMD ["python3", "app.py"]
