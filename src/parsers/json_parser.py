import json

from pathlib import Path
from typing import Iterator, Callable, Optional


def parse_json_file(
    file_path: str,
    on_error: Optional[Callable] = None
) -> Iterator[tuple[int, dict]]:

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Log file not found: {file_path}"
        )

    if not path.is_file():
        raise ValueError(
            f"Path is not a file: {file_path}"
        )

    with path.open("r", encoding="utf-8") as file:

        for line_number, line in enumerate(file, start=1):

            line = line.strip()

            if not line:
                continue

            try:

                event = json.loads(line)

                if not isinstance(event, dict):
                    raise ValueError(
                        "JSON event must be an object"
                    )

                yield line_number, event

            except (json.JSONDecodeError, ValueError) as error:

                if on_error:
                    on_error(
                        line_number,
                        line,
                        str(error)
                    )