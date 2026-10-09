"""Load all bundled sample logs into a running local ULPF API."""

from __future__ import annotations

from pathlib import Path

import httpx


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_SOURCES = (
    "fortigate.log",
    "cisco_asa.log",
    "paloalto.csv",
    "suricata.json",
    "squid.log",
)
API_URL = "http://127.0.0.1:8000"


def main() -> int:
    try:
        with httpx.Client(base_url=API_URL, timeout=60.0) as client:
            print(f"{'Source':<18} {'Lines sent':>10} {'Success':>9} {'Partial':>9} {'Failed':>8}")
            for filename in SAMPLE_SOURCES:
                path = PROJECT_ROOT / "sample_logs" / filename
                lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line]
                with path.open("rb") as sample_file:
                    response = client.post(
                        "/upload",
                        files={"file": (filename, sample_file, "text/plain")},
                    )
                response.raise_for_status()
                counts = response.json()
                print(
                    f"{filename:<18} {len(lines):>10} "
                    f"{counts.get('success', 0):>9} {counts.get('partial', 0):>9} "
                    f"{counts.get('failed', 0):>8}"
                )
    except (OSError, httpx.HTTPError) as error:
        print(
            f"Could not load samples from {API_URL}: {error}\n"
            "Start the API with: uvicorn ulpf.ingest:app --reload"
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
