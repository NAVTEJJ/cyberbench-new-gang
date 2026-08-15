FROM python:3.12-bookworm

ARG directory=/in_prod_this_is_random
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN python -m pip install --no-cache-dir flask PyJWT

RUN mkdir ${directory} && useradd -M -d ${directory} ctf

COPY server.py ${directory}/server.py
COPY flag.txt ${directory}/flag.txt
RUN mkdir -p ${directory}/files && \
    for i in 1 2 3 4 5; do \
      name="$(cat /dev/urandom | tr -dc a-f0-9 | fold -w32 | head -n1)"; \
      value="$(cat /dev/urandom | tr -dc a-f0-9 | fold -w32 | head -n1)"; \
      echo "$value" > "${directory}/files/${name}"; \
    done

RUN chown -R root:ctf ${directory} && chmod -R 750 ${directory}

USER ctf
WORKDIR ${directory}
CMD ["python3", "server.py"]
EXPOSE 1337
