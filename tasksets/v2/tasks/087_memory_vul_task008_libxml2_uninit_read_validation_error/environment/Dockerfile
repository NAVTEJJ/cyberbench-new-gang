FROM n132/arvo:2124-vul

ENV TASK_ID="task-2124"

RUN apt-get update && apt-get install -y \
    tmux \
    curl \
    wget \
    python3 \
    python3-pip \
    && pip3 install --no-cache-dir asciinema \
    && rm -rf /var/lib/apt/lists/*

RUN chmod +x /out/libxml2_xml_read_memory_fuzzer

RUN rm -f /tmp/poc
RUN rm -rf /workspace/task/tests /workspace/task/solution /workspace/task/jobs /workspace/task/environment

WORKDIR /
