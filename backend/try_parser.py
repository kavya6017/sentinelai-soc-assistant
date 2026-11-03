from app.services.ingestion.linux_auth import parse_lines

with open("../data/sample_logs/linux_auth.log", encoding="utf-8") as f:
    result = parse_lines(f, year=2026)

print("events:", len(result.events))
print("skipped:", result.skipped)
print("errors:", len(result.errors))
for e in result.events:
    print(e.timestamp, e.event_type, e.username, e.src_ip, e.status.value)
for err in result.errors:
    print("ERROR line", err.line_number, "-", err.reason)