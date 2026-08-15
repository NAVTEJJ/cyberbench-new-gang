def find_text(data, text, nocase=False, xor=False):
    pat = text.encode()
    hay = data.lower() if nocase else data
    if (pat.lower() if nocase else pat) in hay:
        return True
    if xor:
        for k in range(1, 256):
            xp = bytes(b ^ k for b in pat)
            if (xp.lower() if nocase else xp) in hay:
                return True
    return False

def parse_hex(s):
    out = []
    for t in s.split():
        if t == "??": out.append(("any",))
        elif t.startswith("["):
            a, b = t.strip("[]").split("-"); out.append(("jump", int(a), int(b)))
        else: out.append(("byte", int(t, 16)))
    return out

def match_from(data, toks, pos, idx=0):
    if idx == len(toks): return True
    if pos > len(data): return False
    t = toks[idx]
    if t[0] == "byte":
        return pos < len(data) and data[pos] == t[1] and match_from(data, toks, pos+1, idx+1)
    if t[0] == "any":
        return pos < len(data) and match_from(data, toks, pos+1, idx+1)
    return any(match_from(data, toks, pos+j, idx+1) for j in range(t[1], t[2]+1))

def find_hex(data, s):
    toks = parse_hex(s)
    return any(match_from(data, toks, i) for i in range(len(data)+1))

class RuleScanner:
    def scan(self, rules, sample):
        data = sample.get("bytes", b"")
        sections = {s["name"]: s for s in sample.get("sections", [])}
        imports = {x.lower() for x in sample.get("imports", [])}
        matched_rules = []
        for rule in rules:
            hits = {}
            for name, p in rule.get("patterns", {}).items():
                target = data
                if "section" in p:
                    sec = sections.get(p["section"])
                    if not sec:
                        hits[name] = False; continue
                    target = data[sec["offset"]:sec["offset"]+sec["size"]]
                if "text" in p:
                    hits[name] = find_text(target, p["text"], p.get("nocase", False), p.get("xor", False))
                elif "hex" in p:
                    hits[name] = find_hex(target, p["hex"])
                else:
                    hits[name] = False
            def ev(c):
                if "all" in c: return all(hits.get(x, False) for x in c["all"])
                if "any" in c: return any(hits.get(x, False) for x in c["any"])
                if "n_of" in c:
                    n, names = c["n_of"]; return sum(1 for x in names if hits.get(x, False)) >= n
                if "imports_any" in c: return any(x.lower() in imports for x in c["imports_any"])
                if "section_entropy_gt" in c:
                    sec, val = c["section_entropy_gt"]; return sections.get(sec, {}).get("entropy", 0) > val
                if "and" in c: return all(ev(x) for x in c["and"])
                if "or" in c: return any(ev(x) for x in c["or"])
                if "not" in c: return not ev(c["not"])
                return False
            if ev(rule.get("condition", {})):
                matched_rules.append(rule["name"])
        return sorted(matched_rules)
