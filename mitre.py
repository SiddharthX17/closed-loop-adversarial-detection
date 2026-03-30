from mitreattack.stix20 import MitreAttackData

attack = MitreAttackData("data/enterprise-attack.json")

# get_techniques() returns all — filter by external ID
techniques = attack.get_techniques(include_subtechniques=True)
technique = next(t for t in techniques if any(
    ref.get("external_id") == "T1059.001"
    for ref in t.external_references
))

print(f"Name: {technique.name}")
print(f"Description: {technique.description[:200]}")

# Pull procedure examples
procedures = attack.get_procedure_examples_by_technique(technique.id)

for proc in procedures[:5]:
    print("---")
    print(f"Description: {proc.description}")
