class RiskScorer:

    @staticmethod
    def calculate_score(
        malicious=0,
        suspicious=0,
        failed_logins=0,
        unique_usernames=0,
        commands=0,
        file_transfers=0
    ):

        score = 0
        reasons = []

        # VirusTotal reputation

        if malicious >= 5:
            score += 70
            reasons.append(
                "Multiple VirusTotal malicious detections"
            )

        elif malicious > 0:
            score += 50
            reasons.append(
                "VirusTotal malicious detections"
            )

        if suspicious > 0:
            score += 20
            reasons.append(
                "VirusTotal suspicious detections"
            )

        # Authentication behavior

        if failed_logins >= 20:
            score += 25
            reasons.append(
                "High number of failed login attempts"
            )

        elif failed_logins >= 5:
            score += 15
            reasons.append(
                "Repeated failed login attempts"
            )

        # Username enumeration

        if unique_usernames >= 5:
            score += 10
            reasons.append(
                "Multiple usernames attempted"
            )

        # Command execution

        if commands >= 5:
            score += 10
            reasons.append(
                "Multiple commands executed"
            )

        # File transfer

        if file_transfers > 0:
            score += 25
            reasons.append(
                "File transfer activity detected"
            )

        score = min(score, 100)

        return {
            "risk_score": score,
            "severity": RiskScorer.classify_severity(score),
            "reasons": reasons
        }

    @staticmethod
    def classify_severity(score):

        if score >= 80:
            return "critical"

        if score >= 60:
            return "high"

        if score >= 30:
            return "medium"

        return "low"