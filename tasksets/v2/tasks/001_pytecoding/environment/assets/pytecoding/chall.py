#!/usr/local/bin/python3

bc = bytes.fromhex(input("code? "))


def validate():
    from opcode import opname

    if len(bc) > 72 or len(bc) % 2 != 0:
        print("no")
        exit(1)

    for i in range(0, len(bc), 2):
        [op, arg] = bc[i : i + 2]
        name = opname[op]
        if (
            arg >= 10
            or op >= 129
            or any(
                b in name
                for b in [
                    "<",
                    "GET",
                    "EXTENDED",
                    "INSTRUMENTED",
                    "LOAD",
                    "STORE",
                    "DELETE",
                    "CALL",
                    "RESERVED",
                    "JUMP",
                    "IMPORT",
                    "BINARY_OP_INPLACE_ADD_UNICODE",  # this opcode is incredibly cursed
                ]
            )
        ):
            print("no")
            exit(1)


validate()
del validate


def f():
    pass


f.__code__ = f.__code__.replace(co_code=bc, co_stacksize=4096)
res = f()
print(res)
