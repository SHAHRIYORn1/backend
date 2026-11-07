import sqlite3

conn = sqlite3.connect('soztop.db')

print("=== USERS IN DB ===")
users = conn.execute("SELECT id, username, password_hash FROM users").fetchall()
for u in users:
    print(f"  ID={u[0]}  username={u[1]}  hash_start={u[2][:20]}")
print(f"Total users: {len(users)}")

print("\n=== TABLE SCHEMA ===")
info = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'").fetchone()
print(info[0])

print("\n=== DUPLICATE USERNAMES? ===")
dups = conn.execute("SELECT username, COUNT(*) as cnt FROM users GROUP BY username HAVING cnt > 1").fetchall()
if dups:
    for d in dups:
        print(f"  DUPLICATE: {d[0]} x{d[1]}")
else:
    print("  None — all usernames unique")

conn.close()
