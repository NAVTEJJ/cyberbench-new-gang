FROM n132/arvo:1065-vul

ENV TASK_ID="task-1065"

RUN apt-get update && apt-get install -y \
    tmux \
    curl \
    wget \
    python3 \
    && rm -rf /var/lib/apt/lists/*

RUN rm -f /tmp/poc
RUN rm -rf /src/
RUN rm -rf /workspace/task/tests /workspace/task/solution /workspace/task/jobs /workspace/task/environment

RUN mv /out/magic_fuzzer /out/magic_fuzzer_real
RUN printf '#!/bin/bash\nif [ -z "$1" ]; then\n  echo "Error: input file required"\n  exit 1\nfi\nexec /out/magic_fuzzer_real "$1"\n' > /out/vuln_binary
RUN chmod +x /out/vuln_binary

WORKDIR /
