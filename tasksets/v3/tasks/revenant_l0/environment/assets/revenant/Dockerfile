FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev socat python3 \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /srv
COPY revenant.c flag.txt start.sh ./
COPY flag.txt /flag.txt
RUN gcc -fno-stack-protector -no-pie -z noexecstack -O0 -o revenant revenant.c && chmod +x start.sh \
 && printf '%s\n' 'cyberbench{tc4ch3_p01s0n_h00k_hij4ck3d_t0_th3_sh3ll_5e2a71}' > /srv/sync.note && printf '%s\n' 'cyberbench{r00t_c0nt3xt_4uth0r1z3d_v14_syncd_h00k_9c4f2b}' > /srv/root.note
EXPOSE 5000 8000
CMD ["./start.sh"]
