# AWS Breach Simulation & Incident Response

## Overview

This project demonstrates cloud threat detection and incident response using AWS security services and Stratus Red Team to simulate real-world attack scenarios.

## Attacks Simulated

1. Credential Access — EC2 Password Data Retrieval (`aws.credential-access.ec2-get-password-data`)
2. Defense Evasion — CloudTrail Logging Disabled (`aws.defense-evasion.cloudtrail-stop`)
3. Persistence — Unauthorized Admin User Creation (`aws.persistence.iam-create-admin-user`)

## Tools and Services Used

- Stratus Red Team — Attack simulation framework
- AWS CloudTrail — API activity logging and forensic analysis
- AWS GuardDuty — Threat detection service
- AWS Security Hub — Security findings aggregation

## Key Findings

- CloudTrail successfully logged all attack activity with detailed forensic visibility
- GuardDuty did not generate findings for these attack scenarios, highlighting the importance of manual log analysis
- Detection gaps were identified and remediation strategies documented in the incident report

## Repository Structure

```text
aws-breach-simulation-stratus/
├── reports/
│   └── incident-report.pdf
├── screenshots/
│   ├── attack1-getpassworddata/
│   ├── attack2-stopcloudtrail/
│   └── attack3-iam-admin/
└── README.md