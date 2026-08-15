FROM python:3.11.9

WORKDIR /ctf
RUN useradd -M -d /ctf ctf

COPY magnum_opus.py /ctf/magnum_opus.py
COPY flag.txt /ctf/flag.txt
COPY server.py /ctf/server.py
COPY start.sh /ctf/start.sh

RUN chown -R root:ctf /ctf && \
    chmod -R 750 /ctf && \
    chmod 640 /ctf/flag.txt

USER ctf
CMD ["python3", "/ctf/server.py"]
EXPOSE 1337
