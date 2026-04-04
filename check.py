from mitreattack.stix20 import MitreAttackData
from pipeline.emulator.procedure_interpreter import (
    interpret_procedure,
    build_log_event,
    is_shallow_procedure
)
""
attack = MitreAttackData("data/enterprise-attack.json")

TEST_TECHNIQUES = ["T1059.001", "T1053.005", "T1547.001"]

techniques = attack.get_techniques(include_subtechniques=True)
"""
for tid in TEST_TECHNIQUES:
    tech = next((t for t in techniques
                 if any(r.get("external_id") == tid
                        for r in t.get("external_references", []))), None)

    if not tech:
        print(f"{tid} not found")
        continue

    name = tech.get("name", "")
    tactic = tech.get("kill_chain_phases", [{}])[0].get("phase_name", "")

    procedures = [
        r.get("description", "")
        for r in tech.get("external_references", [])
        if r.get("description")
    ]

    if not procedures:
        print(f"{tid} — no procedures found")
        continue

    print(f"\n{'='*60}")
    print(f"Technique: {tid} — {name}")

    event_generated = False

    for i, procedure in enumerate(procedures):
        if len(procedure) < 50:
            continue

        if is_shallow_procedure(procedure):
            continue

        print(f"\n[Attempt {i+1}]")
        print(f"Procedure: {procedure[:200]}...")

        result = interpret_procedure(tid, name, tactic, procedure)

        print(f"Confidence: {result.get('confidence')}")
        print(f"Reason: {result.get('reason')}")
        print(f"Fields: {result.get('fields')}")

        if result.get("confidence") != "high":
            continue

        event = build_log_event(result, procedure)

        if event:
            print("\n🔥 SUCCESS — LogEvent generated:")
            print(event)
            event_generated = True
            break

    if not event_generated:
        print("\n❌ No valid log event generated for this technique")
"""
tid = "T1059.001"
name = "PowerShell"
tactic = "execution"

procedure = "powershell.exe -enc SQBFAFgA..."

print(f"\n{'='*60}")
print(f"Technique: {tid} — {name}")
print(f"Procedure: {procedure}")

result = interpret_procedure(tid, name, tactic, procedure)

print(f"Confidence: {result.get('confidence')}")
print(f"Reason: {result.get('reason')}")
print(f"Fields: {result.get('fields')}")

event = build_log_event(result, procedure)

print("\n🔥 RESULT:")
print(event)
