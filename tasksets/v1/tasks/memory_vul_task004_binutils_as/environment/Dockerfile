FROM n132/arvo:47101-vul

ENV TASK_ID="task-47101"

RUN apt-get update && apt-get install -y \
    tmux \
    curl \
    wget \
    python3 \
    && rm -rf /var/lib/apt/lists/*

RUN chmod +x /out/fuzz_as

RUN rm -f /tmp/poc
RUN rm -rf /workspace/task/tests /workspace/task/solution /workspace/task/jobs /workspace/task/environment

WORKDIR /
