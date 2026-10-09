import httpx

BASE = "http://127.0.0.1:8000"
LINE = "date=2026-10-03 time=10:15:00 devname=FW1 srcip=10.1.1.5 srcport=51234 dstip=8.8.8.8 dstport=53 proto=17 action=deny policyid=12"

# Check 1: send the raw log
r = httpx.post(f"{BASE}/ingest", json=[LINE])
print("INGEST status:", r.status_code)
print(r.text[:500])

# Check 2: get the clean events
r = httpx.get(f"{BASE}/events", params={"limit": 1})
data = r.json()
events = data if isinstance(data, list) else data.get("events", data.get("items", []))
ev = events[0]
print("\nCLEAN EVENT")
print("action   :", ev.get("action"))
print("protocol :", ev.get("protocol"))
print("timestamp:", ev.get("timestamp"))
print("extras   :", ev.get("vendor_extras"))

# Check 3: trace back to the original
raw_id = ev["raw_event_id"]
r = httpx.get(f"{BASE}/raw/{raw_id}")
print("\nRAW CHECK")
print(r.json())
