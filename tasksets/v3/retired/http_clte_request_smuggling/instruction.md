# CL.TE Request Smuggling Exploit

Craft `/src/request.txt` as a raw HTTP request stream that exploits a front-end `Content-Length` and back-end `Transfer-Encoding` disagreement, causing the backend to receive `GET /admin/flag HTTP/1.1`.
