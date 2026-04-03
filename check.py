from pipeline.emulator.benign_generator import generate_benign_events, save_by_type

events = generate_benign_events(count=20, seed=42)
save_by_type(events)
print(events[0])