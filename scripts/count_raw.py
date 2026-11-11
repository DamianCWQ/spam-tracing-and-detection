"""Count messages and header coverage in downloaded raw sets. Prints counts only (no content).
Run: .venv\\Scripts\\python.exe -I scripts\\count_raw.py <data/raw dir>
"""
import mailbox, email, email.policy, sys, glob, os

raw = sys.argv[1]


def stats(msgs):
    n = rec = auth = 0
    for m in msgs:
        n += 1
        rec += bool(m.get_all("Received"))
        auth += bool(m.get("Authentication-Results"))
    return n, rec, auth


for name in ("nazario-2024/phishing-2024", "nazario-2025/phishing-2025"):
    mb = mailbox.mbox(os.path.join(raw, name))
    n, rec, auth = stats(mb)
    print(f"{name}: messages={n} with_Received={rec} with_AuthResults={auth}")

files = sorted(glob.glob(os.path.join(raw, "phishing-pot", "*.txt")))
msgs = [email.message_from_bytes(open(f, "rb").read(), policy=email.policy.default) for f in files]
n, rec, auth = stats(msgs)
print(f"phishing-pot: messages={n} with_Received={rec} with_AuthResults={auth}")
