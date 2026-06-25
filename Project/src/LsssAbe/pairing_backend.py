import argparse
import base64
import hashlib
import hmac
import json
import re
import secrets
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from py_ecc.bls.hash_to_curve import hash_to_G1
from py_ecc.optimized_bls12_381 import (
    FQ,
    FQ2,
    FQ12,
    G1,
    G2,
    Z1,
    Z2,
    add,
    b,
    b2,
    curve_order,
    is_inf,
    is_on_curve,
    multiply,
    neg,
    normalize,
    pairing,
)


DST_G1 = b"LSSS-ABE-PY-ECC-BLS12381-G1"
KEY_LABEL = b"LSSS-ABE-GT-KEY-V1"


def mod(x):
    return int(x) % curve_order


def random_scalar(nonzero=False):
    if nonzero:
        return secrets.randbelow(curve_order - 1) + 1
    return secrets.randbelow(curve_order)


def read_json(path):
    with open(path, "r", encoding="utf-8-sig") as f:
        return json.load(f)


def write_json(obj, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def safe_file_name_part(text):
    safe = re.sub(r'[\\/:*?"<>|]', "_", text)
    safe = re.sub(r"\s+", "_", safe).strip(" ._")
    return safe or "attr"


def hash_bytes(data):
    return hashlib.sha256(data).digest()


def derive_payload_key(gt_value):
    return hash_bytes(KEY_LABEL + gt_to_bytes(gt_value))


def encrypt_payload(key32, plain):
    iv = secrets.token_bytes(16)
    enc_key = hash_bytes(key32 + b"AES")
    mac_key = hash_bytes(key32 + b"HMAC")
    cipher = AES.new(enc_key, AES.MODE_CBC, iv).encrypt(pad(plain, AES.block_size))
    tag = hmac.new(mac_key, iv + cipher, hashlib.sha256).digest()
    return {
        "nonce": base64.b64encode(iv).decode("ascii"),
        "tag": base64.b64encode(tag).decode("ascii"),
        "data": base64.b64encode(cipher).decode("ascii"),
    }


def decrypt_payload(key32, payload):
    iv = base64.b64decode(payload["nonce"])
    tag = base64.b64decode(payload["tag"])
    cipher = base64.b64decode(payload["data"])
    enc_key = hash_bytes(key32 + b"AES")
    mac_key = hash_bytes(key32 + b"HMAC")
    expected = hmac.new(mac_key, iv + cipher, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("Invalid ciphertext tag.")
    return unpad(AES.new(enc_key, AES.MODE_CBC, iv).decrypt(cipher), AES.block_size)


def g1_to_json(point):
    if is_inf(point):
        return {"type": "G1", "inf": True}
    x, y = normalize(point)
    return {"type": "G1", "x": str(int(x)), "y": str(int(y))}


def g2_to_json(point):
    if is_inf(point):
        return {"type": "G2", "inf": True}
    x, y = normalize(point)
    return {
        "type": "G2",
        "x": [str(int(x.coeffs[0])), str(int(x.coeffs[1]))],
        "y": [str(int(y.coeffs[0])), str(int(y.coeffs[1]))],
    }


def gt_to_json(value):
    return {"type": "GT", "coeffs": [str(int(c)) for c in value.coeffs]}


def g1_from_json(obj):
    if obj.get("inf"):
        return Z1
    point = (FQ(int(obj["x"])), FQ(int(obj["y"])), FQ.one())
    if not is_on_curve(point, b):
        raise ValueError("Invalid G1 point.")
    if not is_inf(multiply(point, curve_order)):
        raise ValueError("Invalid G1 subgroup point.")
    return point


def g2_from_json(obj):
    if obj.get("inf"):
        return Z2
    point = (
        FQ2([int(obj["x"][0]), int(obj["x"][1])]),
        FQ2([int(obj["y"][0]), int(obj["y"][1])]),
        FQ2.one(),
    )
    if not is_on_curve(point, b2):
        raise ValueError("Invalid G2 point.")
    if not is_inf(multiply(point, curve_order)):
        raise ValueError("Invalid G2 subgroup point.")
    return point


def gt_from_json(obj):
    coeffs = obj["coeffs"]
    if len(coeffs) != 12:
        raise ValueError("Invalid GT element.")
    return FQ12(tuple(int(c) for c in coeffs))


def gt_to_bytes(value):
    return b"".join(int(c).to_bytes(48, "big") for c in value.coeffs)


def hash_attr_to_g1(attr):
    return hash_to_G1(attr.encode("utf-8"), DST_G1, hashlib.sha256)


def validate_policy(node):
    if not isinstance(node, dict):
        raise ValueError("Invalid policy: each node must be an object.")
    has_attr = "attr" in node and node["attr"] is not None
    has_children = "children" in node and node["children"] is not None
    if has_attr:
        if not isinstance(node["attr"], str) or node["attr"].strip() == "":
            raise ValueError("Invalid policy: leaf attr must be a non-empty string.")
        if has_children:
            raise ValueError("Invalid policy: leaf node must not have children.")
        return
    if "k" not in node:
        raise ValueError("Invalid policy: internal node must contain k.")
    if not has_children or not isinstance(node["children"], list) or len(node["children"]) == 0:
        raise ValueError("Invalid policy: internal node must have non-empty children.")
    k = int(node["k"])
    if k < 1 or k > len(node["children"]):
        raise ValueError("Invalid policy: k must satisfy 1 <= k <= number of children.")
    for child in node["children"]:
        validate_policy(child)


def gate_random_count(node):
    if "attr" in node and node["attr"] is not None:
        return 0
    total = int(node["k"]) - 1
    for child in node["children"]:
        total += gate_random_count(child)
    return total


def build_gate_index_map(node, state, index_map):
    if "attr" in node and node["attr"] is not None:
        return
    k = int(node["k"])
    indices = []
    for _ in range(k - 1):
        indices.append(state["next"])
        state["next"] += 1
    index_map[id(node)] = indices
    for child in node["children"]:
        build_gate_index_map(child, state, index_map)


def vec_zeros(length):
    return [0 for _ in range(length)]


def vec_unit(length, index):
    v = vec_zeros(length)
    v[index] = 1
    return v


def vec_add(a, b):
    return [mod(x + y) for x, y in zip(a, b)]


def vec_scale(v, k):
    return [mod(x * k) for x in v]


def vec_dot(a, b):
    return mod(sum(x * y for x, y in zip(a, b)))


def convert_policy_to_lsss(policy):
    validate_policy(policy)
    n = 1 + gate_random_count(policy)
    index_map = {}
    build_gate_index_map(policy, {"next": 1}, index_map)
    rows = []
    rho = []

    def walk(node, share):
        if "attr" in node and node["attr"] is not None:
            rows.append([mod(x) for x in share])
            rho.append(node["attr"])
            return
        k = int(node["k"])
        children = node["children"]
        coeffs = [share]
        for idx in index_map[id(node)]:
            coeffs.append(vec_unit(n, idx))
        for pos, child in enumerate(children, start=1):
            child_share = vec_zeros(n)
            for degree in range(k):
                child_share = vec_add(child_share, vec_scale(coeffs[degree], pow(pos, degree, curve_order)))
            walk(child, child_share)

    root = vec_zeros(n)
    root[0] = 1
    walk(policy, root)
    return {"M": rows, "rho": rho, "n": n, "l": len(rows)}


def inv_mod(x):
    x = mod(x)
    if x == 0:
        raise ZeroDivisionError("Cannot invert zero in Zp.")
    return pow(x, curve_order - 2, curve_order)


def solve_weights(M, rho, attrs):
    attr_set = set(attrs)
    row_indices = [i for i, attr in enumerate(rho) if attr in attr_set]
    if not row_indices:
        return None
    n = len(M[0])
    cols = len(row_indices)
    aug = []
    for r in range(n):
        aug.append([mod(M[row_indices[c]][r]) for c in range(cols)] + [1 if r == 0 else 0])

    pivot_cols = []
    pivot_row = 0
    for col in range(cols):
        found = None
        for r in range(pivot_row, n):
            if aug[r][col] != 0:
                found = r
                break
        if found is None:
            continue
        aug[pivot_row], aug[found] = aug[found], aug[pivot_row]
        inv = inv_mod(aug[pivot_row][col])
        aug[pivot_row] = [mod(x * inv) for x in aug[pivot_row]]
        for r in range(n):
            if r == pivot_row:
                continue
            factor = aug[r][col]
            if factor == 0:
                continue
            aug[r] = [mod(aug[r][c] - factor * aug[pivot_row][c]) for c in range(cols + 1)]
        pivot_cols.append(col)
        pivot_row += 1
        if pivot_row == n:
            break

    for r in range(n):
        if all(aug[r][c] == 0 for c in range(cols)) and aug[r][cols] != 0:
            return None

    omega = [0 for _ in range(cols)]
    for r, col in enumerate(pivot_cols):
        omega[col] = aug[r][cols]

    for r in range(n):
        lhs = mod(sum(M[row_indices[c]][r] * omega[c] for c in range(cols)))
        rhs = 1 if r == 0 else 0
        if lhs != rhs:
            return None
    return {"indices": row_indices, "omega": omega}


def cmd_setup(args):
    alpha = random_scalar(nonzero=True)
    a = random_scalar(nonzero=True)
    g1_a = multiply(G1, a)
    egg_alpha = pairing(G2, G1) ** alpha
    public = {
        "scheme": "LSSS-CP-ABE-BLS12-381",
        "p": str(curve_order),
        "g1": g1_to_json(G1),
        "g2": g2_to_json(G2),
        "g1_a": g1_to_json(g1_a),
        "egg_alpha": gt_to_json(egg_alpha),
        "group": {
            "adapter": "PyEccBls12381Pairing",
            "curve": "BLS12-381",
            "scalar_modulus": str(curve_order),
            "real_pairing": True,
            "library": "py-ecc",
        },
    }
    master = {"alpha": str(alpha), "a": str(a)}
    write_json(public, Path(args.out_dir) / "public.json")
    write_json(master, Path(args.out_dir) / "master.json")


def cmd_keygen(args):
    public = read_json(args.pub)
    master = read_json(args.msk)
    attrs = [a.strip() for a in args.attrs.split(",") if a.strip()]
    if not attrs:
        raise ValueError("At least one attribute is required.")
    alpha = int(master["alpha"])
    a = int(master["a"])
    t = random_scalar(nonzero=True)
    K = add(multiply(G1, alpha), multiply(G1, mod(a * t)))
    L = multiply(G2, t)
    kx = {}
    for attr in attrs:
        kx[attr] = g1_to_json(multiply(hash_attr_to_g1(attr), t))
    secret_key = {
        "scheme": public.get("scheme", "LSSS-CP-ABE-BLS12-381"),
        "attrs": attrs,
        "K": g1_to_json(K),
        "L": g2_to_json(L),
        "Kx": kx,
    }
    safe_attrs = [safe_file_name_part(a) for a in attrs]
    write_json(secret_key, Path(args.out_dir) / ("sk_" + "_".join(safe_attrs) + ".json"))


def cmd_encrypt(args):
    public = read_json(args.pub)
    policy = read_json(args.policy)
    plain = Path(args.input).read_bytes()
    g1_a = g1_from_json(public["g1_a"])
    g2 = g2_from_json(public["g2"])
    egg_alpha = gt_from_json(public["egg_alpha"])
    lsss = convert_policy_to_lsss(policy)
    M = lsss["M"]
    rho = lsss["rho"]
    n = lsss["n"]
    rows = lsss["l"]

    s = random_scalar(nonzero=True)
    v = [0 for _ in range(n)]
    u = [0 for _ in range(n)]
    v[0] = s
    u[0] = 0
    for j in range(1, n):
        v[j] = random_scalar()
        u[j] = random_scalar()

    lambdas = [vec_dot(M[i], v) for i in range(rows)]
    blind = [vec_dot(M[i], u) for i in range(rows)]

    message_gt = pairing(g2, G1) ** random_scalar(nonzero=True)
    payload_key = derive_payload_key(message_gt)
    payload = encrypt_payload(payload_key, plain)
    C = message_gt * (egg_alpha ** s)
    C0 = multiply(g2, s)

    Ci = []
    Di = []
    for i in range(rows):
        attr = rho[i]
        h_attr = hash_attr_to_g1(attr)
        ci = add(multiply(g1_a, lambdas[i]), neg(multiply(h_attr, blind[i])))
        di = multiply(g2, blind[i])
        Ci.append(g1_to_json(ci))
        Di.append(g2_to_json(di))

    ciphertext = {
        "scheme": public.get("scheme", "LSSS-CP-ABE-BLS12-381"),
        "policy": policy,
        "lsss": {
            "M": [[str(x) for x in row] for row in M],
            "rho": rho,
        },
        "C": gt_to_json(C),
        "C0": g2_to_json(C0),
        "Ci": Ci,
        "Di": Di,
        "payload": payload,
    }
    write_json(ciphertext, args.output)


def cmd_decrypt(args):
    public = read_json(args.pub)
    secret_key = read_json(args.sk)
    ciphertext = read_json(args.input)
    attrs = secret_key["attrs"]
    rho = ciphertext["lsss"]["rho"]
    M = [[mod(int(x)) for x in row] for row in ciphertext["lsss"]["M"]]
    weights = solve_weights(M, rho, attrs)
    if weights is None:
        raise ValueError("Attributes do not satisfy policy.")

    K = g1_from_json(secret_key["K"])
    L = g2_from_json(secret_key["L"])
    Kx = {attr: g1_from_json(value) for attr, value in secret_key["Kx"].items()}
    C = gt_from_json(ciphertext["C"])
    C0 = g2_from_json(ciphertext["C0"])
    Ci = [g1_from_json(value) for value in ciphertext["Ci"]]
    Di = [g2_from_json(value) for value in ciphertext["Di"]]

    A = FQ12.one()
    for pos, row_index in enumerate(weights["indices"]):
        attr = rho[row_index]
        if attr not in Kx:
            continue
        term = pairing(L, Ci[row_index]) * pairing(Di[row_index], Kx[attr])
        A *= term ** weights["omega"][pos]

    masked = pairing(C0, K) * A.inv()
    message_gt = C * masked.inv()
    plain = decrypt_payload(derive_payload_key(message_gt), ciphertext["payload"])
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(plain)


def build_parser():
    parser = argparse.ArgumentParser(description="BLS12-381 pairing backend for LSSS-CP-ABE.")
    sub = parser.add_subparsers(dest="command", required=True)

    setup = sub.add_parser("setup")
    setup.add_argument("--out-dir", required=True)
    setup.set_defaults(func=cmd_setup)

    keygen = sub.add_parser("keygen")
    keygen.add_argument("--pub", required=True)
    keygen.add_argument("--msk", required=True)
    keygen.add_argument("--attrs", required=True)
    keygen.add_argument("--out-dir", required=True)
    keygen.set_defaults(func=cmd_keygen)

    encrypt = sub.add_parser("encrypt")
    encrypt.add_argument("--pub", required=True)
    encrypt.add_argument("--policy", required=True)
    encrypt.add_argument("--input", required=True)
    encrypt.add_argument("--output", required=True)
    encrypt.set_defaults(func=cmd_encrypt)

    decrypt = sub.add_parser("decrypt")
    decrypt.add_argument("--pub", required=True)
    decrypt.add_argument("--sk", required=True)
    decrypt.add_argument("--input", required=True)
    decrypt.add_argument("--output", required=True)
    decrypt.set_defaults(func=cmd_decrypt)
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        raise SystemExit(str(exc))
