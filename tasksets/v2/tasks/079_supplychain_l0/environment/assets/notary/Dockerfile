FROM python:3.11-slim
WORKDIR /app
COPY notary.py .
ENV PORT=8200
ENV NOTARY_TOKEN=notary-build-token-sc9x2p
ENV ARTIFACT_STORE_TOKEN=artifact-store-tkn-7g4nq1
ENV REGISTRY_URL=http://registry:5000
EXPOSE 8200
CMD ["python3","notary.py"]
