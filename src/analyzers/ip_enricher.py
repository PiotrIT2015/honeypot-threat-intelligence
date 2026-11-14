import json
import time
import ipaddress
import argparse

from pathlib import Path
from datetime import datetime, timezone

from src.integrations.virustotal_client import (
    VirusTotalClient
)


class IPEnricher:

    def __init__(
        self,
        input_file,
        output_file,
        cache_file
    ):

        self.input_file = Path(input_file)
        self.output_file = Path(output_file)
        self.cache_file = Path(cache_file)

        self.client = VirusTotalClient()

        self.cache = {}

        self.processed = 0
        self.skipped = 0
        self.errors = 0

        self.load_cache()

    def load_cache(self):

        if not self.cache_file.exists():
            return

        with self.cache_file.open(
            "r",
            encoding="utf-8"
        ) as file:

            for line in file:

                try:

                    record = json.loads(line)

                    ip = record.get("ip")

                    if ip:
                        self.cache[ip] = record

                except json.JSONDecodeError:
                    continue

    def save_cache(self):

        self.cache_file.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        with self.cache_file.open(
            "w",
            encoding="utf-8"
        ) as file:

            for record in self.cache.values():

                file.write(
                    json.dumps(
                        record,
                        ensure_ascii=False
                    ) + "\n"
                )

    @staticmethod
    def is_public_ip(ip):

        try:

            address = ipaddress.ip_address(ip)

            return address.is_global

        except ValueError:

            return False

    def extract_ips(self):

        if not self.input_file.exists():
            raise FileNotFoundError(
                f"Input file not found: {self.input_file}"
            )

        unique_ips = set()

        with self.input_file.open(
            "r",
            encoding="utf-8"
        ) as file:

            for line in file:

                try:

                    event = json.loads(line)

                    ip = event.get("src_ip")

                    if ip and self.is_public_ip(ip):

                        unique_ips.add(ip)

                except json.JSONDecodeError:

                    self.errors += 1

        return sorted(unique_ips)

    def enrich(self):

        print("[INFO] Starting IP Enrichment")

        if not self.input_file.exists():
            raise FileNotFoundError(
                f"Input file not found: {self.input_file}"
            )

        self.output_file.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        ips = self.extract_ips()

        print(
            f"[INFO] Unique public IPs found: {len(ips)}"
        )

        try:

            with self.output_file.open(
                "w",
                encoding="utf-8"
            ) as output:

                for ip in ips:

                    if ip in self.cache:

                        result = self.cache[ip]

                        self.skipped += 1

                        print(
                            f"[CACHE] {ip}"
                        )

                    else:

                        print(
                            f"[VT] Checking {ip}"
                        )

                        result = self.client.get_ip_report(
                            ip
                        )

                        result["checked_at"] = (
                            datetime.now(
                                timezone.utc
                            ).isoformat()
                        )

                        self.cache[ip] = result

                        self.processed += 1

                        if result["status"] == "rate_limited":

                            print(
                                "[WARNING] VirusTotal rate limit reached."
                            )

                            self.errors += 1

                            del self.cache[ip]

                            break

                        if result["status"] != "success":

                            self.errors += 1

                        # Public API: max 4 requests/minute.
                        time.sleep(16)

                    output.write(
                        json.dumps(
                            result,
                            ensure_ascii=False
                        ) + "\n"
                    )

        finally:

            self.save_cache()

            self.client.close()

        print("\n[INFO] Enrichment completed")

        print(
            f"[INFO] Processed: {self.processed}"
        )

        print(
            f"[INFO] Cached: {self.skipped}"
        )

        print(
            f"[INFO] Errors: {self.errors}"
        )

        print(
            f"[INFO] Output: {self.output_file}"
        )


def main():

    parser = argparse.ArgumentParser(
        description="VirusTotal IP Enrichment"
    )

    parser.add_argument(
        "--input",
        default="data/processed/events.jsonl"
    )

    parser.add_argument(
        "--output",
        default="data/threat_intelligence/ip_enrichment.jsonl"
    )

    parser.add_argument(
        "--cache",
        default="data/threat_intelligence/ip_cache.jsonl"
    )

    args = parser.parse_args()

    enricher = IPEnricher(
        input_file=args.input,
        output_file=args.output,
        cache_file=args.cache
    )

    enricher.enrich()


if __name__ == "__main__":
    main()