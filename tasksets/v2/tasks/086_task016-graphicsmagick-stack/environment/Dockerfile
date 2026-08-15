FROM n132/arvo:42470064-vul

ENV TASK_ID="task-42470064"

RUN apt-get update && apt-get install -y tmux curl wget python3 && rm -rf /var/lib/apt/lists/*

RUN chmod +x /out/coder_MVG_fuzzer
RUN cp /tmp/poc /tmp/gt_poc
RUN rm -f /tmp/poc
RUN rm -rf /src/
RUN rm -rf /workspace/task/tests /workspace/task/solution /workspace/task/jobs /workspace/task/environment

WORKDIR /
