"""Demonstrate zero-code parser onboarding against a running ULPF API."""

import sys

import httpx


BASE = "http://127.0.0.1:8000"
SAMPLES = [
    "ts=2026-10-03T10:20:01 device=AcmeFW client_ip=192.168.1.10 sport=40001 server_ip=1.1.1.1 dport=443 verdict=denied user=ravi",
    "ts=2026-10-03T10:21:02 device=AcmeFW client_ip=192.168.1.11 sport=40002 server_ip=8.8.8.8 dport=53 verdict=allowed user=anu",
    "ts=2026-10-03T10:22:03 device=AcmeFW client_ip=192.168.1.12 sport=40003 server_ip=9.9.9.9 dport=443 verdict=denied user=sam",
    "ts=2026-10-03T10:23:04 device=AcmeFW client_ip=192.168.1.13 sport=40004 server_ip=1.0.0.1 dport=80 verdict=allowed user=mira",
    "ts=2026-10-03T10:24:05 device=AcmeFW client_ip=192.168.1.14 sport=40005 server_ip=208.67.222.222 dport=443 verdict=denied user=dev",
]
NEW_LINE = (
    "ts=2026-10-03T10:30:00 device=AcmeFW client_ip=10.9.9.9 "
    "sport=50000 server_ip=4.4.4.4 dport=25 verdict=denied user=zoya"
)


def report_check(label: str, passed: bool) -> bool:
    """Print a named result and return whether it passed."""
    print(f"{'PASS' if passed else 'FAIL'}: {label}")
    return passed


def main() -> int:
    checks: list[bool] = []
    try:
        with httpx.Client(base_url=BASE, timeout=10.0) as client:
            autogen_response = client.post(
                "/autogen",
                json={
                    "samples": SAMPLES,
                    "name": "acmefw",
                    "vendor": "Acme",
                    "product": "AcmeFW",
                    "save": True,
                },
            )
            print("AUTOGEN status:", autogen_response.status_code)
            autogen_response.raise_for_status()
            generated = autogen_response.json()
            print("\nGENERATED YAML")
            print(generated.get("yaml", ""))
            print("CONFIDENCE REPORT")
            print(generated.get("confidence", {}))

            ingest_response = client.post("/ingest", json=[NEW_LINE])
            print("\nINGEST status:", ingest_response.status_code)
            ingest_response.raise_for_status()

            events_response = client.get("/events", params={"limit": 1})
            events_response.raise_for_status()
            data = events_response.json()
            if isinstance(data, list):
                events = data
            elif isinstance(data, dict):
                events = data.get("events", data.get("items", []))
            else:
                events = []
            if not events or not isinstance(events[0], dict):
                raise ValueError("The API returned no event to inspect")
            event = events[0]

            source = event.get("source", {})
            src = event.get("src", {})
            dst = event.get("dst", {})
            print("\nCLEAN EVENT")
            print("source vendor/product:", source.get("vendor"), "/", source.get("product"))
            print("src ip/port:", src.get("ip"), "/", src.get("port"))
            print("dst ip/port:", dst.get("ip"), "/", dst.get("port"))
            print("action:", event.get("action"))
            print("user:", event.get("user"))
            print("timestamp:", event.get("timestamp"))
            print("parse_status:", event.get("parse_status"))
            print("parse_score:", event.get("parse_score"))
            print("vendor_extras:", event.get("vendor_extras"))

            raw_response = client.get(f"/raw/{event['raw_event_id']}")
            raw_response.raise_for_status()
            raw = raw_response.json()
            print("\nRAW CHECK")
            print("original line:", raw.get("raw_text"))
            print("verified:", raw.get("verified"))

            checks.extend(
                [
                    report_check("src.ip == 10.9.9.9", src.get("ip") == "10.9.9.9"),
                    report_check("dst.ip == 4.4.4.4", dst.get("ip") == "4.4.4.4"),
                    report_check('action == "block"', event.get("action") == "block"),
                    report_check('user == "zoya"', event.get("user") == "zoya"),
                    report_check(
                        'parse_status == "success"',
                        event.get("parse_status") == "success",
                    ),
                    report_check("raw verified == true", raw.get("verified") is True),
                ]
            )
    except httpx.RequestError as error:
        print(
            f"Could not connect to {BASE}: {error}\n"
            "Is the server running? Start it with: uvicorn ulpf.ingest:app --reload"
        )
        return 1
    except (httpx.HTTPStatusError, ValueError, KeyError) as error:
        print(f"Autogen demo failed: {error}")
        return 1

    return 0 if all(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
