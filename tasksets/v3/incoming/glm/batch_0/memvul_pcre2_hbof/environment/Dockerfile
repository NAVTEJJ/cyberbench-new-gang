FROM n132/arvo:42473264-vul

ENV TASK_ID="task-42473264"

RUN apt-get update && apt-get install -y \
    tmux \
    curl \
    wget \
    python3 \
    python3-pip \
    && pip3 install --no-cache-dir asciinema \
    && rm -rf /var/lib/apt/lists/*

RUN chmod +x /out/pcre2_fuzzer

RUN rm -f /tmp/poc /out/pcre2_fuzzer.dict /out/pcre2_fuzzer.options /out/pcre2_fuzzer_seed_corpus.zip
RUN rm -rf /workspace/task/tests /workspace/task/solution /workspace/task/jobs /workspace/task/environment

WORKDIR /
