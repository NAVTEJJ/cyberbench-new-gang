class SmugglingDetector:
    def analyze(self, raw):
        if not isinstance(raw, (bytes, bytearray)) or b"\r\n\r\n" not in raw:
            return "BAD_CHUNK"
        head, body = bytes(raw).split(b"\r\n\r\n", 1)
        lines = head.split(b"\r\n")
        if not lines or not lines[0].endswith(b" HTTP/1.1"):
            return "BAD_CHUNK"
        headers = {}
        for line in lines[1:]:
            if not line or line[:1] in (b" ", b"\t") or b":" not in line:
                return "OBS_FOLD"
            name, val = line.split(b":", 1)
            lname = name.decode("latin1").lower()
            headers.setdefault(lname, []).append(val.decode("latin1").strip())
        cls = []
        for val in headers.get("content-length", []):
            for part in val.split(","):
                part = part.strip()
                if not part.isdigit():
                    return "DUP_CL"
                cls.append(int(part))
        if len(set(cls)) > 1:
            return "DUP_CL"
        te_parts = [x.strip().lower() for x in ",".join(headers.get("transfer-encoding", [])).split(",") if x.strip()]
        if "identity" in te_parts or te_parts.count("chunked") > 1 or ("chunked" in te_parts and te_parts[-1] != "chunked"):
            return "BAD_CHUNK"
        chunked = "chunked" in te_parts
        if cls and chunked:
            return "CLTE"
        if chunked:
            pos = 0
            while True:
                end = body.find(b"\r\n", pos)
                if end < 0:
                    return "BAD_CHUNK"
                size_s = body[pos:end].split(b";", 1)[0]
                try:
                    size = int(size_s, 16)
                except ValueError:
                    return "BAD_CHUNK"
                pos = end + 2
                if size == 0:
                    trailer_start = pos
                    end_trailers = body.find(b"\r\n\r\n", trailer_start)
                    if body[trailer_start:trailer_start + 2] == b"\r\n":
                        end_pos = trailer_start + 2
                    elif end_trailers >= 0:
                        trailer_block = body[trailer_start:end_trailers]
                        for line in trailer_block.split(b"\r\n"):
                            if not line or line[:1] in (b" ", b"\t") or b":" not in line:
                                return "BAD_CHUNK"
                            name = line.split(b":", 1)[0].decode("latin1").lower()
                            if name in ("content-length", "transfer-encoding"):
                                return "BAD_CHUNK"
                        end_pos = end_trailers + 4
                    else:
                        return "BAD_CHUNK"
                    rest = body[end_pos:]
                    if rest in (b"", b"\r\n"):
                        return "SAFE"
                    return "TECL" if rest.startswith((b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ")) else "BAD_CHUNK"
                if len(body) < pos + size + 2 or body[pos + size:pos + size + 2] != b"\r\n":
                    return "BAD_CHUNK"
                pos += size + 2
        if cls:
            return "SAFE" if len(body) == cls[0] else "BAD_CHUNK"
        return "SAFE" if body == b"" else "TECL"
