import json
import csv

input_file = "data\\covenant_persistwmi_2019-12-05044734.json"   # your file
output_file = "output.csv"

rows = []
all_keys = set()

# Step 1: Read and collect all keys
with open(input_file, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
            rows.append(record)
            all_keys.update(record.keys())
        except json.JSONDecodeError:
            continue  # skip bad lines

# Step 2: Write to CSV
all_keys = sorted(all_keys)

with open(output_file, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=all_keys)
    writer.writeheader()

    for row in rows:
        writer.writerow(row)

print(f"Converted {len(rows)} records to {output_file}")
