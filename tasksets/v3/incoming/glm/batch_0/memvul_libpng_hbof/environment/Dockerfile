FROM n132/arvo:42498959-vul

ENV TASK_ID="task-42498959"

RUN apt-get update && apt-get install -y \
    tmux \
    curl \
    wget \
    python3 \
    python3-pip \
    && pip3 install --no-cache-dir asciinema \
    && rm -rf /var/lib/apt/lists/*

RUN chmod +x /out/libpng_read_fuzzer

RUN rm -f /tmp/poc /out/libpng_read_fuzzer.dict /out/libpng_read_fuzzer.options /out/libpng_read_fuzzer_seed_corpus.zip /out/png.dict
RUN rm -rf /workspace/task/tests /workspace/task/solution /workspace/task/jobs /workspace/task/environment
RUN find /src -name "*.png" -delete 2>/dev/null; rm -rf /src/libpng/contrib 2>/dev/null; true

WORKDIR /
