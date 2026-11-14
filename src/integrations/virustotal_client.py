import os
import time
import requests

from dotenv import load_dotenv


load_dotenv()


class VirusTotalClient:

    def __init__(self):

        self.api_key = os.getenv("VT_API_KEY")

        self.base_url = os.getenv(
            "VT_BASE_URL",
            "https://www.virustotal.com/api/v3"
        )

        if not self.api_key:
            raise ValueError(
                "VT_API_KEY is missing in .env"
            )

        self.headers = {
            "accept": "application/json",
            "x-apikey": self.api_key
        }

        self.session = requests.Session()

        self.session.headers.update(
            self.headers
        )

    def get_ip_report(self, ip_address):

        url = (
            f"{self.base_url}/ip_addresses/"
            f"{ip_address}"
        )

        try:

            response = self.session.get(
                url,
                timeout=30
            )

            if response.status_code == 404:
                return {
                    "status": "not_found",
                    "ip": ip_address
                }

            if response.status_code == 429:
                return {
                    "status": "rate_limited",
                    "ip": ip_address
                }

            response.raise_for_status()

            result = response.json()

            attributes = result.get(
                "data", {}
            ).get(
                "attributes", {}
            )

            stats = attributes.get(
                "last_analysis_stats", {}
            )

            return {

                "status": "success",

                "ip": ip_address,

                "reputation": attributes.get(
                    "reputation"
                ),

                "country": attributes.get(
                    "country"
                ),

                "asn": attributes.get(
                    "asn"
                ),

                "owner": attributes.get(
                    "as_owner"
                ),

                "network": attributes.get(
                    "network"
                ),

                "malicious": stats.get(
                    "malicious", 0
                ),

                "suspicious": stats.get(
                    "suspicious", 0
                ),

                "harmless": stats.get(
                    "harmless", 0
                ),

                "undetected": stats.get(
                    "undetected", 0
                ),

                "total_votes": attributes.get(
                    "total_votes", {}
                ),

                "last_analysis_date": attributes.get(
                    "last_analysis_date"
                ),

                "tags": attributes.get(
                    "tags", []
                )

            }

        except requests.exceptions.Timeout:

            return {
                "status": "timeout",
                "ip": ip_address
            }

        except requests.exceptions.HTTPError as error:

            return {
                "status": "http_error",
                "ip": ip_address,
                "error": str(error)
            }

        except requests.exceptions.RequestException as error:

            return {
                "status": "connection_error",
                "ip": ip_address,
                "error": str(error)
            }

        except ValueError as error:

            return {
                "status": "invalid_response",
                "ip": ip_address,
                "error": str(error)
            }

    def close(self):

        self.session.close()