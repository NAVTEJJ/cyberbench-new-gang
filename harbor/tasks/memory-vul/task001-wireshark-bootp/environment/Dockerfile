FROM n132/arvo:1273-vul
ENV TASK_ID="task-1273"
RUN apt-get update && apt-get install -y tmux curl wget python3 && rm -rf /var/lib/apt/lists/*
RUN chmod +x /out/fuzzshark_udp_port-bootp
RUN rm -f /tmp/poc
RUN rm -rf /workspace/task/tests /workspace/task/solution /workspace/task/jobs /workspace/task/environment
WORKDIR /
