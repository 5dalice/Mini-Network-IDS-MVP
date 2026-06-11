from ids.sigma_engine import load_sigma_rules

rules = load_sigma_rules()

print(f"Loaded {len(rules)} Sigma rules")

for rule in rules:
    print(rule["title"])
