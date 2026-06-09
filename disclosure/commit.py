"""SHA-3 Commitment — cryptographic proof of discovery timestamp"""

import hashlib
import json
from datetime import datetime, timezone


class SHA3Committer:
    def commit(self, finding: dict) -> dict:
        timestamp = datetime.now(timezone.utc).isoformat()
        payload = {
            "bug_type": finding.get("bug_type", ""),
            "location_hash": hashlib.sha3_256(finding.get("location", "").encode()).hexdigest()[:32],
            "impact": finding.get("impact", ""),
            "severity": finding.get("severity", ""),
            "timestamp": timestamp,
        }
        payload_json = json.dumps(payload, sort_keys=True)
        commitment_hash = hashlib.sha3_256(payload_json.encode()).hexdigest()
        return {
            "algorithm": "SHA3-256",
            "hash": commitment_hash,
            "timestamp": timestamp,
            "note": "Proves discovery date without revealing exploitable details.",
        }

    def verify(self, finding: dict, commitment: dict) -> bool:
        payload = {
            "bug_type": finding.get("bug_type", ""),
            "location_hash": hashlib.sha3_256(finding.get("location", "").encode()).hexdigest()[:32],
            "impact": finding.get("impact", ""),
            "severity": finding.get("severity", ""),
            "timestamp": commitment.get("timestamp", ""),
        }
        computed = hashlib.sha3_256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        return computed == commitment.get("hash", "")
