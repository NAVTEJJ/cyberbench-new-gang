from ops import ops
import dis

names = ()
consts = ()
bd = list(__builtins__.__dict__)
print({v: bd.index(v) for v in ["exec", "print", "breakpoint"]})

cod = """
# load globals + builtins
COPY 7
COPY 7
COPY 1
# remove first 9 keys
UNPACK_EX 9
BUILD_TUPLE 9
POP_TOP
# stack will have 3 keys, then "breakpoint", then an array of the rest
UNPACK_EX 4
BUILD_TUPLE 3
POP_TOP
# construct the string "breakpoint()"
BUILD_TUPLE 0
FORMAT_SIMPLE
BUILD_STRING 2
# stack has an array of rest, then "breakpoint()"
SWAP 2
UNPACK_EX 8
BUILD_TUPLE 7
POP_TOP
# stack has an array of rest, then "exec"
SWAP 2
UNPACK_EX 9
BUILD_TUPLE 9
POP_TOP
UNPACK_EX 9
BUILD_TUPLE 9
POP_TOP
UNPACK_EX 4
BUILD_TUPLE 3
POP_TOP
# stack is [globals, builtins, "breakpoint()", "exec", slop, "print"]
COPY 5
COPY 4
BUILD_TUPLE 1
# stack is [globals, builtins, "breakpoint()", "exec", slop, "print", builtins, ("exec",)]
MATCH_KEYS
# stack is [globals, builtins, "breakpoint()", "exec", slop, "print", builtins, ("exec",), (exec,)]
UNPACK_EX 1
# stack is [globals, builtins, "breakpoint()", "exec", slop, "print", builtins, ("exec",), [], exec]
COPY 5
# stack is [globals, builtins, "breakpoint()", "exec", slop, "print", builtins, ("exec",), [], exec, "print"]
SWAP 2
# stack is [globals, builtins, "breakpoint()", "exec", slop, "print", builtins, ("exec",), [], "print", exec]
MAP_ADD 9
SWAP 7
RETURN_VALUE
""".strip()

bc = b""
for c in cod.split("\n"):
    if c.startswith("#"):
        continue
    l = c.split()
    if len(l) == 1 or l[1].startswith("*"):
        l.insert(1, "1")
    if len(l) == 2:
        l.append("*1")
    [a, b, c] = l
    if not c.startswith("*"):
        raise ValueError("bad mult")
    bc += bytes([ops[a], int(b)] * int(c[1:]))

def f():
    return

f.__code__ = f.__code__.replace(co_names=names, co_consts=consts, co_code=bc, co_stacksize=128)

print(bc.hex())
dis.dis(f)
p = print
res = f()
print(res)
