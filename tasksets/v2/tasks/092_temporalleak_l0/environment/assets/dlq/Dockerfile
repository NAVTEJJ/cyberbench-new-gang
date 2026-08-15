FROM python:3.11-slim
WORKDIR /app
COPY dlq.py .
ENV PORT=8200
EXPOSE 8200
CMD ["python3","dlq.py"]
