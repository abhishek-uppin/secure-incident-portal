# Decision Log

## Decisions
### D-01: Topic: Secure Incident Portal
- **Date:** 10/11/2026
- **Phase:** Planning
- **Decision:** Build a portal where employees report incidents and analsyts review and investigate them. 
- **Why (security reason):** The portal has three roles with different privileges, so least privilege is required. Incident reports contain sensitive data so confidentiality matters as only reporting Employee, analysts and admins can see them. Status changes must be restricted to analysts (SoD) to protect integrity and an audit log supports accountability / non-repudiation.
- **Alternatives considered:** Vulnerability Tracker was considered but rejected because it is more complex to build under the submission time frame.
- **Evidence / follow-up:** 
    - Security requirement: SoD (role based access check)
    - Test case: Employee changes ID in URL (IDOR)
    - Security requirement: Accountability (audit log)

## Lessons Learned