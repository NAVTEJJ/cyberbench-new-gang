FROM python:3.11-slim
WORKDIR /app
COPY builder.py .
ENV PORT=8100
ENV NOTARY_TOKEN=notary-build-token-sc9x2p
EXPOSE 8100
CMD ["python3","builder.py"]
