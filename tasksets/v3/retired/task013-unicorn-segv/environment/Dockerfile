FROM n132/arvo:42470492-vul

ENV TASK_ID="task-42470492"

RUN apt-get update && apt-get install -y tmux curl wget python3 && rm -rf /var/lib/apt/lists/*

RUN chmod +x /out/fuzz_emu_m68k_be
RUN cp /tmp/poc /tmp/gt_poc
RUN rm -f /tmp/poc
RUN rm -rf /src/
RUN rm -rf /workspace/task/tests /workspace/task/solution /workspace/task/jobs /workspace/task/environment

WORKDIR /
