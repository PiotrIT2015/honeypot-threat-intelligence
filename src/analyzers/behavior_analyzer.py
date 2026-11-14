from collections import defaultdict


class BehaviorAnalyzer:

    def analyze(self, events):

        results = defaultdict(
            lambda: {
                "total_events": 0,
                "failed_logins": 0,
                "successful_logins": 0,
                "commands": 0,
                "file_transfers": 0,
                "unique_usernames": set(),
                "event_types": set()
            }
        )

        for event in events:

            ip = event.get("src_ip")

            if not ip:
                continue

            record = results[ip]

            record["total_events"] += 1

            event_type = event.get("event_type")

            eventid = event.get("eventid", "")

            record["event_types"].add(
                event_type or "unknown"
            )

            # Authentication

            if eventid == "cowrie.login.failed":

                record["failed_logins"] += 1

            elif eventid == "cowrie.login.success":

                record["successful_logins"] += 1

            # Username enumeration

            username = event.get("username")

            if username:
                record["unique_usernames"].add(
                    username
                )

            # Commands

            if event_type == "command":

                record["commands"] += 1

            # File transfers

            if event_type == "file_transfer":

                record["file_transfers"] += 1

        normalized_results = {}

        for ip, record in results.items():

            normalized_results[ip] = {

                "total_events": record["total_events"],

                "failed_logins": record["failed_logins"],

                "successful_logins": record["successful_logins"],

                "commands": record["commands"],

                "file_transfers": record["file_transfers"],

                "unique_usernames": len(
                    record["unique_usernames"]
                ),

                "event_types": sorted(
                    record["event_types"]
                )

            }

        return normalized_results