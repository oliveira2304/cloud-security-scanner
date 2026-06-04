"""
checks/ — Registry and multi-region orchestration.

REGISTRY maps service name (CLI --services flag) to its run() function.
Each run() accepts an AWSClient and returns List[Finding].

Multi-region scanning:
  run_all_regions() uses ThreadPoolExecutor to scan N regions in parallel.
  It creates a regional AWSClient via client.for_region(region) — no extra
  STS call per region. All findings are tagged with their region.
  All scan errors go into the shared client.errors list.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from cloudscan.checks import ec2, iam, lambda_checks, logging_checks, rds, s3
from cloudscan.models import Finding

logger = logging.getLogger(__name__)

REGISTRY: dict = {
    "s3":      s3.run,
    "iam":     iam.run,
    "ec2":     ec2.run,
    "rds":     rds.run,
    "lambda":  lambda_checks.run,
    "logging": logging_checks.run,
}

# Services that are global (not region-specific).
# When multi-region scanning, these run only once against the primary region.
GLOBAL_SERVICES = {"iam"}

# Maximum parallel region workers.
# AWS has per-region API rate limits; 5 is conservative and safe for most accounts.
_MAX_WORKERS = 5


def run_all_regions(
    client,          # AWSClient
    selected_services: list[str],
    regions: list[str],
    progress_callback=None,  # Optional callable(region, service, n_findings)
) -> List[Finding]:
    """
    Run selected checks across all given regions in parallel.

    Strategy:
      - Global services (IAM) run once on the primary region — IAM is account-wide.
      - Regional services run in parallel across all regions.
      - Each regional AWSClient shares the same session and error list.
      - Findings are tagged with region via finding.region = region.
    """
    all_findings: List[Finding] = []

    # Run global services once
    global_svcs = [s for s in selected_services if s in GLOBAL_SERVICES]
    for service_name in global_svcs:
        findings = _run_service(client, service_name, client.region)
        if progress_callback:
            progress_callback(client.region, service_name, len(findings))
        all_findings.extend(findings)

    # Run regional services in parallel across all regions
    regional_svcs = [s for s in selected_services if s not in GLOBAL_SERVICES]
    if not regional_svcs:
        return all_findings

    tasks = [
        (region, service_name)
        for region in regions
        for service_name in regional_svcs
    ]

    # Create one regional client per region (not one per region×service).
    # All regional clients share the same boto3 session and errors list.
    regional_clients = {region: client.for_region(region) for region in regions}

    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
        futures = {
            pool.submit(_run_service, regional_clients[region], service_name, region): (region, service_name)
            for region, service_name in tasks
        }

        for future in as_completed(futures):
            region, service_name = futures[future]
            try:
                findings = future.result()
                if progress_callback:
                    progress_callback(region, service_name, len(findings))
                all_findings.extend(findings)
            except Exception as e:
                logger.error("Unexpected error scanning %s/%s: %s", region, service_name, e)

    return all_findings


def _run_service(regional_client, service_name: str, region: str) -> List[Finding]:
    """Run one service check for one region, tagging each finding with region."""
    check_fn = REGISTRY[service_name]
    findings = check_fn(regional_client)

    for f in findings:
        if f.region is None:
            f.region = region

    return findings
