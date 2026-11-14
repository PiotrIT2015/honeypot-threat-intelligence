from datetime import datetime, timezone
from typing import Any


def classify_event(eventid: str | None) -> str:

    if not eventid:
        return "unknown"

    eventid = eventid.lower()

    if eventid in (
        "cowrie.session.connect",
    ):
        return "connection"

    if eventid in (
        "cowrie.login.failed",
        "cowrie.login.success",
    ):
        return "authentication"

    if eventid in (
        "cowrie.command.input",
    ):
        return "command"

    if eventid in (
        "cowrie.session.file_download",
        "cowrie.session.file_upload",
    ):
        return "file_transfer"

    if eventid in (
        "cowrie.session.closed",
        "cowrie.session.params",
    ):
        return "session"

    if "login" in eventid:
        return "authentication"

    if "command" in eventid:
        return "command"

    if "download" in eventid or "upload" in eventid:
        return "file_transfer"

    if "connect" in eventid:
        return "connection"

    if "session" in eventid:
        return "session"

    return "other"


def normalize_event(event: dict[str, Any]) -> dict:

    normalized = {

        "timestamp": event.get("timestamp"),

        "eventid": event.get("eventid"),

        "event_type": classify_event(
            event.get("eventid")
        ),

        "session": event.get("session"),

        "src_ip": event.get("src_ip"),

        "protocol": event.get("protocol"),

        "username": event.get("username"),

        "password": event.get("password"),

        "input": event.get("input"),

        "message": event.get("message"),

        "sensor": event.get("sensor"),

        "processed_at": datetime.now(
            timezone.utc
        ).isoformat(),

        "raw_event": event
    }

    return normalized