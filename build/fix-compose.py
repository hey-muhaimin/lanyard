p = "/opt/lanyard/production.compose.yml"
lines = open(p).read().splitlines()
out = [l for l in lines if 'DATABASE_URL: "${DATABASE_URL}"' not in l]
open(p, "w").write("\n".join(out) + "\n")
print("removed_lines:", len(lines) - len(out))
print("has_env_file:", sum(1 for l in out if "env_file" in l))
