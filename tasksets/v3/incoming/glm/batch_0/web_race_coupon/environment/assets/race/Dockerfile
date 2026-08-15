FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir "flask==3.0.3"
COPY app.py /app/app.py
ENV FLAG="cyberbench{r4c3_c0nd1t10n_l1m1t_0v3rrun}"
EXPOSE 5000
CMD ["python", "-u", "/app/app.py"]
