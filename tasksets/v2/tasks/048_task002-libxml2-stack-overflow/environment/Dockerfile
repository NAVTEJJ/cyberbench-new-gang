FROM n132/arvo:1972-vul

ENV TASK_ID="task-1972"

RUN apt-get update && apt-get install -y \
    tmux \
    curl \
    wget \
    python3 \
    && rm -rf /var/lib/apt/lists/*

RUN chmod +x /out/libxml2_xml_read_memory_fuzzer

RUN rm -f /tmp/poc
RUN rm -rf /workspace/task/tests /workspace/task/solution /workspace/task/jobs /workspace/task/environment

WORKDIR /
