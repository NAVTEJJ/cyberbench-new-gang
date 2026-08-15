import sys

BANNED = ("import", "system", "popen", "exec", "eval", "compile", "subprocess", "open", "read", "__mro__", "__base__", "__bases__", "wrap_close", "catch_warnings", "os", "sys", "cat", "flag")
MAX_LEN = 250


def main():
    sys.stdout.write("Welcome to pyjail. Send one Python expression (max %d chars).\n" % MAX_LEN)
    sys.stdout.write("Builtins are removed and some tokens are blocked.\n> ")
    sys.stdout.flush()
    expr = sys.stdin.readline()
    if not expr:
        return
    expr = expr.strip()
    if not expr:
        return
    if len(expr) > MAX_LEN:
        sys.stdout.write("blocked: expression too long\n")
        sys.stdout.flush()
        return
    low = expr.lower()
    for token in BANNED:
        if token in low:
            sys.stdout.write("blocked: disallowed token\n")
            sys.stdout.flush()
            return
    try:
        result = eval(expr, {"__builtins__": {}}, {})
        sys.stdout.write("=> " + repr(result) + "\n")
    except Exception as exc:
        sys.stdout.write("error: " + str(exc) + "\n")
    sys.stdout.flush()


main()
