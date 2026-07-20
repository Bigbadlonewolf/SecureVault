#!/usr/bin/env python3
"""
SecureVault: GCP Security Detection & Response Pipeline
Architect: Lanre Oluokun | Implementation: AI-assisted
License: MIT

Publish a simulated Security Command Center finding to the SecureVault Pub/Sub
topic. Useful for local integration tests and post-deployment smoke tests.

Examples:
    python scripts/simulate_finding.py --project my-project --finding-class PUBLIC_BUCKET_ACL
    python scripts/simulate_finding.py --project my-project --finding-class OPEN_FIREWALL
    python scripts/simulate_finding.py --project my-project --severity HIGH
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict


def _sample_finding(finding_class: str, severity: str) -> Dict[str, Any]:
    """Return a realistic SCC finding payload for the requested class/severity."""
    now = datetime.now(timezone.utc).isoformat()
    project = os.environ.get("PROJECT_ID", "unknown-project")

    # Real SCC findings set findingClass to a fixed enum (e.g. MISCONFIGURATION)
    # and put the specific detector name in category. Templates below use the
    # internal --finding-class value only to select the realistic shape.
    templates = {
        "PUBLIC_BUCKET_ACL": {
            "name": f"projects/{project}/sources/123/findings/sim-{finding_class}-{now}",
            "parent": f"projects/{project}/sources/123",
            "resourceName": f"//storage.googleapis.com/{project}-public-bucket",
            "state": "ACTIVE",
            "category": "PUBLIC_BUCKET_ACL",
            "severity": severity,
            "findingClass": "MISCONFIGURATION",
            "eventTime": now,
            "createTime": now,
            "sourceProperties": {},
        },
        "OPEN_FIREWALL": {
            "name": f"projects/{project}/sources/123/findings/sim-{finding_class}-{now}",
            "parent": f"projects/{project}/sources/123",
            "resourceName": f"//compute.googleapis.com/projects/{project}/global/firewalls/allow-all-ssh",
            "state": "ACTIVE",
            "category": "OPEN_FIREWALL",
            "severity": severity,
            "findingClass": "MISCONFIGURATION",
            "eventTime": now,
            "createTime": now,
            "sourceProperties": {},
        },
        "OVER_PRIVILEGED_SA": {
            "name": f"projects/{project}/sources/123/findings/sim-{finding_class}-{now}",
            "parent": f"projects/{project}/sources/123",
            "resourceName": f"//iam.googleapis.com/projects/{project}/serviceAccounts/overprivileged@{project}.iam.gserviceaccount.com",
            "state": "ACTIVE",
            "category": "OVER_PRIVILEGED_SERVICE_ACCOUNT",
            "severity": severity,
            "findingClass": "MISCONFIGURATION",
            "eventTime": now,
            "createTime": now,
            "sourceProperties": {},
        },
    }

    if finding_class in templates:
        return templates[finding_class]

    # Generic fallback for classes like PUBLIC_DATASET, etc.
    return {
        "name": f"projects/{project}/sources/123/findings/sim-{finding_class}-{now}",
        "parent": f"projects/{project}/sources/123",
        "resourceName": f"//cloudresourcemanager.googleapis.com/projects/{project}",
        "state": "ACTIVE",
        "category": finding_class,
        "severity": severity,
        "findingClass": "MISCONFIGURATION",
        "eventTime": now,
        "createTime": now,
        "sourceProperties": {},
    }


def _publish(project_id: str, topic_id: str, payload: Dict[str, Any]) -> str:
    """Publish a JSON payload to a Pub/Sub topic; return the message ID."""
    # Import here so the script can still be imported for testing without GCP creds.
    from google.cloud import pubsub_v1

    publisher = pubsub_v1.PublisherClient()
    topic_path = publisher.topic_path(project_id, topic_id)

    # SCC notifications wrap the finding in a "finding" key.
    message = {"finding": payload}
    data = json.dumps(message).encode("utf-8")

    future = publisher.publish(topic_path, data)
    return future.result()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Publish a simulated SCC finding to SecureVault's Pub/Sub topic."
    )
    parser.add_argument(
        "--project",
        default=os.environ.get("PROJECT_ID"),
        help="GCP project ID (defaults to PROJECT_ID env var)",
    )
    parser.add_argument(
        "--topic",
        default="scc-findings",
        help="Pub/Sub topic name (default: scc-findings)",
    )
    parser.add_argument(
        "--finding-class",
        default="PUBLIC_BUCKET_ACL",
        help="Finding class to simulate (default: PUBLIC_BUCKET_ACL)",
    )
    parser.add_argument(
        "--severity",
        default=None,
        help="SCC severity to override (default: HIGH for generic, CRITICAL for mapped classes)",
    )
    args = parser.parse_args()

    if not args.project:
        print(
            "Error: --project is required or set the PROJECT_ID environment variable.",
            file=sys.stderr,
        )
        return 1

    mapped_classes = {"PUBLIC_BUCKET_ACL", "OPEN_FIREWALL", "OVER_PRIVILEGED_SA"}
    severity = args.severity or ("CRITICAL" if args.finding_class in mapped_classes else "HIGH")

    finding = _sample_finding(args.finding_class.upper(), severity.upper())
    print(f"Publishing {finding['category']} ({finding['severity']}) finding to {args.topic}...")

    try:
        message_id = _publish(args.project, args.topic, finding)
        print(f"Published message ID: {message_id}")
    except Exception as exc:  # pylint: disable=broad-except
        print(f"Failed to publish message: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
