import json
import argparse

from pathlib import Path

from src.parsers.json_parser import parse_json_file
from src.parsers.event_parser import normalize_event


class CowrieCollector:

    def __init__(
        self,
        input_file,
        output_file,
        error_file
    ):

        self.input_file = Path(input_file).expanduser()
        self.output_file = Path(output_file)
        self.error_file = Path(error_file)

        self.processed_count = 0
        self.parse_error_count = 0
        self.normalization_error_count = 0

    def write_error(
        self,
        errors,
        line_number,
        raw_line,
        error
    ):

        errors.write(
            json.dumps(
                {
                    "line": line_number,
                    "error": error,
                    "raw_line": raw_line
                },
                ensure_ascii=False
            ) + "\n"
        )

        self.parse_error_count += 1

    def collect(self):

        print("[INFO] Starting Cowrie Collector")

        if not self.input_file.exists():
            raise FileNotFoundError(
                f"Input file not found: {self.input_file}"
            )

        if not self.input_file.is_file():
            raise ValueError(
                "Input path must be a file"
            )

        if self.input_file.resolve() == self.output_file.resolve():
            raise ValueError(
                "Input and output files cannot be identical"
            )

        self.output_file.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        self.error_file.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        with (
            self.output_file.open(
                "w",
                encoding="utf-8"
            ) as output,

            self.error_file.open(
                "w",
                encoding="utf-8"
            ) as errors
        ):

            def handle_parse_error(
                line_number,
                raw_line,
                error
            ):

                self.write_error(
                    errors,
                    line_number,
                    raw_line,
                    error
                )

            for line_number, event in parse_json_file(
                str(self.input_file),
                on_error=handle_parse_error
            ):

                try:

                    normalized = normalize_event(event)

                    output.write(
                        json.dumps(
                            normalized,
                            ensure_ascii=False
                        ) + "\n"
                    )

                    self.processed_count += 1

                except Exception as error:

                    errors.write(
                        json.dumps(
                            {
                                "line": line_number,
                                "error": str(error),
                                "event": event
                            },
                            ensure_ascii=False
                        ) + "\n"
                    )

                    self.normalization_error_count += 1

        print("\n[INFO] Collection completed")

        print(
            f"[INFO] Processed events: "
            f"{self.processed_count}"
        )

        print(
            f"[INFO] JSON parsing errors: "
            f"{self.parse_error_count}"
        )

        print(
            f"[INFO] Normalization errors: "
            f"{self.normalization_error_count}"
        )

        print(
            f"[INFO] Output: {self.output_file}"
        )

        print(
            f"[INFO] Errors: {self.error_file}"
        )


def main():

    parser = argparse.ArgumentParser(
        description="Cowrie Log Collector"
    )

    parser.add_argument(
        "--input",
        default="~/cowrie/var/log/cowrie/cowrie.json",
        help="Path to Cowrie JSON log"
    )

    parser.add_argument(
        "--output",
        default="data/processed/events.jsonl",
        help="Path to normalized events"
    )

    parser.add_argument(
        "--errors",
        default="data/errors/collector_errors.jsonl",
        help="Path to collector errors"
    )

    args = parser.parse_args()

    collector = CowrieCollector(
        input_file=args.input,
        output_file=args.output,
        error_file=args.errors
    )

    collector.collect()


if __name__ == "__main__":
    main()