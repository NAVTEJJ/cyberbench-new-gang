FROM n132/arvo:42470017-vul

ENV TASK_ID="task-42470017"

RUN apt-get update && apt-get install -y \
    tmux \
    curl \
    wget \
    python3 \
    && rm -rf /var/lib/apt/lists/*

RUN chmod +x /out/curl_fuzzer_http

RUN rm -f /tmp/poc

RUN rm -rf /workspace/task/tests /workspace/task/solution /workspace/task/jobs /workspace/task/environment

WORKDIR /
