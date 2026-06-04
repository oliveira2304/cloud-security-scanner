"""
checks/ — Each module exposes a single run(client: AWSClient) -> List[Finding] function.

Adding a new service check:
  1. Create checks/newservice.py
  2. Implement run(client) -> List[Finding]
  3. Register it in REGISTRY below
"""

from cloudscan.checks import ec2, iam, s3, logging_checks

# Maps service name (CLI flag) to its run function.
# Order matters — it controls display order in the report.
REGISTRY: dict = {
    "s3": s3.run,
    "iam": iam.run,
    "ec2": ec2.run,
    "logging": logging_checks.run,
}
