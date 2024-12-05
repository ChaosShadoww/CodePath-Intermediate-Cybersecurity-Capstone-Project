# CodePath-Intermediate-Cybersecurity-Capstone-Project
This repository contains the materials and reports for the capstone project completed as part of the CodePath Intermediate Cybersecurity course. The project focuses on detecting and analyzing unauthorized access attempts to an AWS S3 bucket honeypot using monitoring tools and implementing security strategies based on the findings.

# Project Overview
The project demonstrates the following key cybersecurity concepts:

- Analyzing CloudTrail logs using tools like Splunk and Catalyst to gather evidence and generate threat intelligence.
- Identifying malicious IP addresses, attack patterns, and user agents targeting the honeypot.
- Developing remediation strategies to enhance the security posture of real-world assets.

# Key Features
- Monitoring Sources: Utilized AWS CloudTrail to track API activity, such as unauthorized ListObjects and HeadBucket calls.
- Threat Intelligence: Correlated malicious IPs with threat databases using VirusTotal and AbuseIPDB.
- Case Management: Documented incidents and analysis in Catalyst for tracking and reporting.
- Remediation Recommendations: Proposed actionable security measures based on observed attack patterns.

# Technologies and Tools
- AWS CloudTrail: For monitoring API calls and tracking activity.
- Splunk: For analyzing logs and generating insights.
- Catalyst: Case management and incident tracking.
- VirusTotal: Correlation of malicious IPs with known threats.
- AbuseIPDB: Verifying the reputation of suspicious IPs.
- SQL: For querying and analyzing structured data from logs.

# Usage
This repository provides:

- Documentation: Insights into monitoring, triage, and threat intelligence.
- Honeypot Logs: Sample logs from the AWS S3 bucket honeypot.
- Incident Analysis: Detailed reports of observed attack behaviors and remediation strategies.

# Findings
- Malicious activity primarily involved automated tools attempting HeadBucket and ListObjects API calls.
- Multiple malicious IP addresses flagged in threat intelligence databases.
- Suspicious API call sequences based on honeypot activity.

# Future Work
- Deploy additional honeypots with varied configurations to diversify threat insights.
- Automate threat detection using AWS GuardDuty or Security Hub.
- Conduct red team exercises to simulate attacks using gathered intelligence.




  
