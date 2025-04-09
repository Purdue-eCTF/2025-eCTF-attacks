import json

outer_pairs = json.load(open("./outer_pairs.json"))
inner_pair = {"ct": "aa5ce39475c6a31519cfc1575e9e708b",
              "pt": "808b9922ecb697d3163d8f919c06527e"}


list_of_opt = [int(i["pt"], 16) for i in outer_pairs]

goal = int("639c11858b287e794a3df3b00f0bfd39", 16) ^^ int(inner_pair["ct"], 16)
sub = bytes.fromhex("639c11858b287e794a3df3b00f0bfd39")

F = GF(2)

matrix = matrix(F, [list(bin(i)[2:].rjust(128, "0")) for i in list_of_opt]).T
vec = vector(F, list(bin(goal)[2:].rjust(128, "0")))

print(matrix)
print(vec)

def xor(a, b):
    return bytes(m ^^ n for m, n in zip(a, b))

sol = matrix.solve_right(vec)

test = b"\x00"*16
xor_count = 0
needed_pair = []
for i, v in zip(sol, outer_pairs):
    if i == 1:
        test = xor(test, bytes.fromhex(v['pt']))
        xor_count += 1
        needed_pair.append(v)

print(xor_count)
print(test, xor(bytes.fromhex(inner_pair["ct"]), sub))

print(needed_pair)
