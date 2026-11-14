import json
import argparse

from pathlib import Path
from datetime import datetime, timezone

from src.analyzers.behavior_analyzer import (
    BehaviorAnalyzer
)

from src.analyzers.risk_scorer import (
    RiskScorer
)


class IOCAnalysisEngine:

    def __init__(
        self,
        events_file,
        enrichment_file,
        output_file,
        alerts_file
    ):

        self.events_file = Path(events_file)
        self.enrichment_file = Path(enrichment_file)

        self.output_file = Path(output_file)
        self.alerts_file = Path(alerts_file)

        self.behavior_analyzer = BehaviorAnalyzer()

        self.risk_scorer = RiskScorer()

        self.events = []
        self.enrichment = {}

        self.errors = 0

    def load_jsonl(self, file_path):

        records = []

        if not file_path.exists():
            raise FileNotFoundError(
                f"File not found: {file_path}"
            )

        with file_path.open(
            "r",
            encoding="utf-8"
        ) as file:

            for line_number, line in enumerate(
                file,
                start=1
            ):

                try:

                    record = json.loads(line)

                    if isinstance(record, dict):
                        records.append(record)

                except json.JSONDecodeError:

                    self.errors += 1

                    print(
                        f"[WARNING] Invalid JSON: "
                        f"{file_path}, line {line_number}"
                    )

        return records

    def load_data(self):

        print("[INFO] Loading Cowrie events")

        self.events = self.load_jsonl(
            self.events_file
        )

        print(
            f"[INFO] Events loaded: {len(self.events)}"
        )

        print("[INFO] Loading VirusTotal enrichment")

        enrichment_records = self.load_jsonl(
            self.enrichment_file
        )

        for record in enrichment_records:

            ip = record.get("ip")

            if ip:
                self.enrichment[ip] = record

        print(
            f"[INFO] IP reports loaded: "
            f"{len(self.enrichment)}"
        )

    def analyze(self):

        print("[INFO] Starting IOC analysis")

        behavior_results = (
            self.behavior_analyzer.analyze(
                self.events
            )
        )

        analysis_results = []
        alerts = []

        for ip, behavior in behavior_results.items():

            vt_report = self.enrichment.get(
                ip,
                {}
            )

            vt_status = vt_report.get(
                "status",
                "not_checked"
            )

            malicious = 0
            suspicious = 0

            # Use VirusTotal counts only when a report
            # was successfully retrieved.

            if vt_status == "success":

                malicious = vt_report.get(
                    "malicious",
                    0
                ) or 0

                suspicious = vt_report.get(
                    "suspicious",
                    0
                ) or 0

            risk = self.risk_scorer.calculate_score(

                malicious=malicious,

                suspicious=suspicious,

                failed_logins=behavior[
                    "failed_logins"
                ],

                unique_usernames=behavior[
                    "unique_usernames"
                ],

                commands=behavior[
                    "commands"
                ],

                file_transfers=behavior[
                    "file_transfers"
                ]

            )

            result = {

                "ip": ip,

                "analyzed_at": datetime.now(
                    timezone.utc
                ).isoformat(),

                "behavior": behavior,

                "threat_intelligence": {

                    "status": vt_status,

                    "malicious": malicious,

                    "suspicious": suspicious,

                    "country": vt_report.get(
                        "country"
                    ),

                    "asn": vt_report.get(
                        "asn"
                    ),

                    "owner": vt_report.get(
                        "owner"
                    )

                },

                "risk": risk

            }

            analysis_results.append(result)

            if risk["severity"] in (
                "medium",
                "high",
                "critical"
            ):

                alerts.append({

                    "alert_id": (
                        f"IOC-{len(alerts) + 1:05d}"
                    ),

                    "created_at": datetime.now(
                        timezone.utc
                    ).isoformat(),

                    "ip": ip,

                    "severity": risk["severity"],

                    "risk_score": risk["risk_score"],

                    "reasons": risk["reasons"],

                    "status": "new"

                })

        return analysis_results, alerts

    def save_results(
        self,
        analysis_results,
        alerts
    ):

        self.output_file.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        self.alerts_file.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        with self.output_file.open(
            "w",
            encoding="utf-8"
        ) as file:

            for record in analysis_results:

                file.write(
                    json.dumps(
                        record,
                        ensure_ascii=False
                    ) + "\n"
                )

        with self.alerts_file.open(
            "w",
            encoding="utf-8"
        ) as file:

            for alert in alerts:

                file.write(
                    json.dumps(
                        alert,
                        ensure_ascii=False
                    ) + "\n"
                )

        summary = {

            "generated_at": datetime.now(
                timezone.utc
            ).isoformat(),

            "total_events": len(self.events),

            "analyzed_ips": len(analysis_results),

            "total_alerts": len(alerts),

            "severity": {

                "low": 0,

                "medium": 0,

                "high": 0,

                "critical": 0

            },

            "errors": self.errors

        }

        for result in analysis_results:

            severity = result["risk"]["severity"]

            summary["severity"][severity] += 1

        summary_file = (
            self.output_file.parent /
            "analysis_summary.json"
        )

        with summary_file.open(
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                summary,
                file,
                indent=4,
                ensure_ascii=False
            )

        print("\n[INFO] Analysis completed")

        print(
            f"[INFO] Analyzed IPs: "
            f"{len(analysis_results)}"
        )

        print(
            f"[INFO] Alerts generated: "
            f"{len(alerts)}"
        )

        print(
            f"[INFO] Errors: {self.errors}"
        )

        print(
            f"[INFO] Results: {self.output_file}"
        )

        print(
            f"[INFO] Alerts: {self.alerts_file}"
        )

        print(
            f"[INFO] Summary: {summary_file}"
        )

    def run(self):

        self.load_data()

        analysis_results, alerts = self.analyze()

        self.save_results(
            analysis_results,
            alerts
        )


def main():

    parser = argparse.ArgumentParser(
        description="IOC Analysis Engine"
    )

    parser.add_argument(
        "--events",
        default="data/processed/events.jsonl"
    )

    parser.add_argument(
        "--enrichment",
        default=(
            "data/threat_intelligence/"
            "ip_enrichment.jsonl"
        )
    )

    parser.add_argument(
        "--output",
        default=(
            "data/analysis/ioc_analysis.jsonl"
        )
    )

    parser.add_argument(
        "--alerts",
        default="data/alerts/alerts.jsonl"
    )

    args = parser.parse_args()

    engine = IOCAnalysisEngine(

        events_file=args.events,

        enrichment_file=args.enrichment,

        output_file=args.output,

        alerts_file=args.alerts

    )

    engine.run()


if __name__ == "__main__":
    main()