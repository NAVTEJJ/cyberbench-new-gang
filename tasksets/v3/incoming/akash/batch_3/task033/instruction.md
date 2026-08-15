# Redis RESP Command Injection Stream

Create `/src/request.resp`, a raw RESP byte stream for a synthetic Redis gateway. The gateway appends attacker key material into a backend request without validating CRLF. Your stream must make the backend execute an additional `CONFIG GET requirepass` command. Submit only raw request bytes.
