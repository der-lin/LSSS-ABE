from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "figures"
OUT.mkdir(parents=True, exist_ok=True)


plt.rcParams["font.family"] = "DejaVu Sans"
plt.rcParams["axes.unicode_minus"] = False


def add_box(ax, xy, width, height, text, face="#f5f7fb", edge="#2f4053", size=10):
    box = FancyBboxPatch(
        xy,
        width,
        height,
        boxstyle="round,pad=0.02,rounding_size=0.03",
        linewidth=1.6,
        edgecolor=edge,
        facecolor=face,
    )
    ax.add_patch(box)
    ax.text(
        xy[0] + width / 2,
        xy[1] + height / 2,
        text,
        ha="center",
        va="center",
        fontsize=size,
        color="#17202a",
        wrap=True,
    )
    return box


def add_arrow(ax, start, end, text=None, rad=0.0):
    arrow = FancyArrowPatch(
        start,
        end,
        arrowstyle="->",
        mutation_scale=14,
        linewidth=1.4,
        color="#34495e",
        connectionstyle=f"arc3,rad={rad}",
    )
    ax.add_patch(arrow)
    if text:
        mx = (start[0] + end[0]) / 2
        my = (start[1] + end[1]) / 2
        ax.text(mx, my + 0.03, text, ha="center", va="bottom", fontsize=8, color="#34495e")


def add_line(ax, start, end):
    ax.plot(
        [start[0], end[0]],
        [start[1], end[1]],
        color="#34495e",
        linewidth=1.35,
        solid_capstyle="round",
    )


def save(fig, name):
    fig.savefig(OUT / name, dpi=220, bbox_inches="tight")
    plt.close(fig)


def system_architecture():
    fig, ax = plt.subplots(figsize=(11.6, 6.5))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    ax.set_title("LSSS-ABE System Architecture", fontsize=15, weight="bold", pad=18)

    add_box(ax, (0.34, 0.84), 0.32, 0.10, "CLI\nbin/lsss-abe.ps1", "#e8f0fe", "#1f5fbf", 11)
    add_box(ax, (0.34, 0.69), 0.32, 0.10, "Core Module\nLsssAbe.psm1", "#eaf7ee", "#227a3d", 11)

    support_frame = FancyBboxPatch(
        (0.025, 0.35),
        0.57,
        0.25,
        boxstyle="round,pad=0.012,rounding_size=0.025",
        linewidth=1.1,
        edgecolor="#d6dbdf",
        facecolor="#fbfcfd",
    )
    policy_frame = FancyBboxPatch(
        (0.605, 0.35),
        0.37,
        0.25,
        boxstyle="round,pad=0.012,rounding_size=0.025",
        linewidth=1.1,
        edgecolor="#d6dbdf",
        facecolor="#fbfcfd",
    )
    ax.add_patch(support_frame)
    ax.add_patch(policy_frame)
    label_box = dict(facecolor="#fbfcfd", edgecolor="none", pad=1.0)
    ax.text(0.055, 0.575, "Foundation services", ha="left", va="center", fontsize=8.5, color="#566573", bbox=label_box)
    ax.text(0.635, 0.575, "Policy and data services", ha="left", va="center", fontsize=8.5, color="#566573", bbox=label_box)

    modules = [
        ((0.045, 0.405), "Number Theory\nmod / inverse\nvectors", "#fff4e6", "#b56b00"),
        ((0.235, 0.405), "GroupAdapter\nExponentSimulation\nBLS12-381 Pairing", "#fff4e6", "#b56b00"),
        ((0.425, 0.405), "Crypto Primitives\nRNG / SHA-256\nAES-CBC + HMAC", "#fff4e6", "#b56b00"),
        ((0.625, 0.405), "LSSS Layer\npolicy tree -> matrix\nGaussian elimination", "#fff4e6", "#b56b00"),
        ((0.815, 0.405), "JSON I/O\nPK / MSK\nSK / CT", "#fff4e6", "#b56b00"),
    ]
    for xy, text, face, edge in modules:
        add_box(ax, xy, 0.15, 0.13, text, face, edge, 7.9)

    add_box(ax, (0.28, 0.08), 0.44, 0.13, "CP-ABE Algorithms\nSetup / KeyGen / Encrypt / Decrypt", "#f6e9ff", "#7d3c98", 10)

    module_centers = [0.12, 0.31, 0.50, 0.71, 0.88]
    top_bus_y = 0.635
    bottom_bus_y = 0.31

    add_arrow(ax, (0.50, 0.84), (0.50, 0.79))
    add_arrow(ax, (0.50, 0.69), (0.50, top_bus_y))
    add_line(ax, (0.12, top_bus_y), (0.88, top_bus_y))
    for x in module_centers:
        add_arrow(ax, (x, top_bus_y), (x, 0.535))

    for x in module_centers:
        add_line(ax, (x, 0.405), (x, bottom_bus_y))
    add_line(ax, (0.12, bottom_bus_y), (0.88, bottom_bus_y))
    add_arrow(ax, (0.50, bottom_bus_y), (0.50, 0.21))

    save(fig, "system_architecture.png")


def encrypt_decrypt_flow():
    fig, ax = plt.subplots(figsize=(11, 6))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    ax.set_title("Encryption and Decryption Data Flow", fontsize=15, weight="bold", pad=18)

    left = [
        ((0.04, 0.72), "Policy JSON\n(A AND B) OR C"),
        ((0.04, 0.51), "Plaintext\nmessage.txt"),
        ((0.27, 0.72), "Build LSSS\n(M, rho)"),
        ((0.27, 0.51), "AES-CBC + HMAC-SHA256\npayload"),
        ((0.50, 0.62), "Ciphertext JSON\npolicy + LSSS\nC, C0, Ci, Di + payload"),
    ]
    for xy, text in left:
        add_box(ax, xy, 0.18, 0.13, text, "#edf7ff", "#2874a6", 9)

    right = [
        ((0.73, 0.72), "Secret Key JSON\nattrs S, K, L, Kx"),
        ((0.73, 0.51), "Solve LSSS weights\n$M_I^T\\omega=e_1$"),
        ((0.73, 0.30), "Recover mExp\nverify HMAC\nAES decrypt"),
        ((0.73, 0.09), "Output Plaintext"),
    ]
    for xy, text in right:
        add_box(ax, xy, 0.20, 0.13, text, "#f0f8ed", "#2e7d32", 9)

    add_arrow(ax, (0.22, 0.785), (0.27, 0.785))
    add_arrow(ax, (0.22, 0.575), (0.27, 0.575))
    add_arrow(ax, (0.45, 0.785), (0.50, 0.70))
    add_arrow(ax, (0.45, 0.575), (0.50, 0.64))
    add_arrow(ax, (0.68, 0.68), (0.73, 0.57), "CT")
    add_arrow(ax, (0.83, 0.72), (0.83, 0.64), "S")
    add_arrow(ax, (0.83, 0.51), (0.83, 0.43))
    add_arrow(ax, (0.83, 0.30), (0.83, 0.22))

    ax.text(0.11, 0.93, "Encrypt", ha="center", fontsize=12, weight="bold", color="#2874a6")
    ax.text(0.83, 0.93, "Decrypt", ha="center", fontsize=12, weight="bold", color="#2e7d32")

    save(fig, "encrypt_decrypt_flow.png")


def policy_lsss_matrix():
    fig, ax = plt.subplots(figsize=(10.8, 5.9))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    ax.set_title("Policy Tree to LSSS Matrix", fontsize=15, weight="bold", pad=18)

    ax.text(0.22, 0.86, "Access policy tree", ha="center", fontsize=11, weight="bold", color="#1f5fbf")

    add_box(ax, (0.13, 0.71), 0.18, 0.10, "OR\n1-of-2", "#e8f0fe", "#1f5fbf", 10)
    add_box(ax, (0.075, 0.49), 0.18, 0.10, "AND\n2-of-2", "#e8f0fe", "#1f5fbf", 10)
    add_box(ax, (0.305, 0.49), 0.12, 0.10, "C", "#fff4e6", "#b56b00", 12)
    add_box(ax, (0.035, 0.25), 0.12, 0.10, "A", "#fff4e6", "#b56b00", 12)
    add_box(ax, (0.215, 0.25), 0.12, 0.10, "B", "#fff4e6", "#b56b00", 12)

    add_arrow(ax, (0.18, 0.71), (0.165, 0.59))
    add_arrow(ax, (0.26, 0.71), (0.365, 0.59))
    add_arrow(ax, (0.125, 0.49), (0.095, 0.35))
    add_arrow(ax, (0.205, 0.49), (0.275, 0.35))

    ax.text(0.61, 0.82, "M =", fontsize=14, weight="bold")
    matrix_text = "[[1, 1],\n [1, 2],\n [1, 0]]"
    ax.text(
        0.69,
        0.72,
        matrix_text,
        fontsize=16,
        family="monospace",
        bbox=dict(boxstyle="round,pad=0.4", facecolor="#f7f9fb", edgecolor="#566573"),
    )
    ax.text(0.61, 0.43, "rho = [A, B, C]", fontsize=14, family="monospace")
    ax.text(
        0.56,
        0.23,
        "Rows A and B reconstruct (1,0):\n2*(1,1) - 1*(1,2) = (1,0)\nRow C alone reconstructs (1,0).",
        fontsize=10,
        bbox=dict(boxstyle="round,pad=0.35", facecolor="#eef8f0", edgecolor="#2e7d32"),
    )

    save(fig, "policy_lsss_matrix.png")


def experiment_results():
    fig, ax = plt.subplots(figsize=(10.8, 7.2))
    ax.axis("off")
    ax.set_title("Smoke Test Scenarios", fontsize=15, weight="bold", pad=18)

    data = [
        ["Scenario", "Input / Operation", "Policy or Object", "Expected", "Observed"],
        ["1", "{A, B}", "(A AND B) OR C", "Decrypt", "Passed"],
        ["2", "{C}", "(A AND B) OR C", "Decrypt", "Passed"],
        ["3", "{A}", "(A AND B) OR C", "Reject", "Passed"],
        ["4", "role:admin", "single-attribute policy", "Safe filename + decrypt", "Passed"],
        ["5", "tampered payload.tag", "ciphertext JSON", "Reject HMAC", "Passed"],
        ["6", "{D, F}", "2-of-3(D,E,F)", "Decrypt", "Passed"],
        ["7", "{D}", "2-of-3(D,E,F)", "Reject", "Passed"],
        ["8", "{X}", "duplicate X AND X", "Decrypt", "Passed"],
        ["9", "bad k / missing fields / empty attr", "invalid policies", "Reject", "Passed"],
    ]
    table = ax.table(cellText=data, loc="center", cellLoc="center")
    table.auto_set_font_size(False)
    table.set_fontsize(8.8)
    table.scale(1, 1.55)
    for (row, col), cell in table.get_celld().items():
        cell.set_edgecolor("#566573")
        if row == 0:
            cell.set_facecolor("#2f4053")
            cell.get_text().set_color("white")
            cell.get_text().set_weight("bold")
        elif col == 4:
            cell.set_facecolor("#eaf7ee")
        else:
            cell.set_facecolor("#f8f9fa")

    save(fig, "experiment_results.png")


def main():
    system_architecture()
    encrypt_decrypt_flow()
    policy_lsss_matrix()
    experiment_results()
    print(f"Generated figures in {OUT}")


if __name__ == "__main__":
    main()
