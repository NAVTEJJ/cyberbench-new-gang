FROM python:3.14-slim

RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev socat && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY chall.py /app/run
COPY printflag.c /app/printflag.c
RUN gcc -O2 -DFLAG='"dice{mildly_toxic_python_bytecoding}"' /app/printflag.c -o /app/printflag && rm /app/printflag.c
RUN chmod 755 /app/run && chmod 111 /app/printflag

EXPOSE 5000
CMD ["socat", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:/app/run,stderr"]
