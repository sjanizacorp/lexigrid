# LexiGrid

LexiGrid is a self-hosted governance, risk, and compliance application. It gives risk owners, control owners, and auditors a shared place to track what can go wrong, which safeguards apply, what the evidence shows, and who owns the next action.

## What you can do with LexiGrid

- **Connect risks to safeguards.** Maintain a risk register and link risks to policies, controls, frameworks, and requirements. Track which safeguards address each risk and who owns the follow-up.
- **Build a governance library.** Import structured CSV files or extract candidates from PDFs, then review the records before adding them to the library.
- **Assess and report on risk.** Use assessment profiles based on NIST SP 800-30, FAIR, and ISO/IEC 27005. Export assessment reports as PDF, CSV, or JSON.
- **Run evidence-based audits.** Record safeguard applicability, implementation, and tested effectiveness separately. Attach evidence, assign remediation, and track independent review.
- **Operate in your environment.** Deploy on your own infrastructure. Administrators can configure Microsoft Entra ID or AD FS for single sign-on.

## How LexiGrid uses AI

- **Find relevant safeguards.** LexiGrid scans your governance library for candidate policies, controls, frameworks, and requirements. The configured model explains which candidates may apply to the risk so reviewers can inspect the records behind each suggestion.
- **Propose risk assessments.** The model uses the risk record, linked evidence, control information, and reviewer answers to propose likelihood and impact ratings, explain its reasoning, and suggest treatment actions. It can flag missing information. Authorized reviewers can keep the current rating or apply an eligible proposal through the review workflow.
- **Apply a structured assessment method.** Select a profile such as NIST SP 800-30, FAIR, or ISO/IEC 27005. LexiGrid uses the model to structure the analysis and produces a report with the assessment context and evidence references.
- **Choose where the model runs.** Administrators can run AI locally with Ollama or explicitly enable a supported cloud provider. The [AI assessment guide](docs/distribution/LexiGrid_AI_Evidence_Grounded_Assessment_Guide.pdf) covers configuration and review.

## Download and install

[Download LexiGrid for Linux and PostgreSQL](https://github.com/sjanizacorp/lexigrid/releases/download/client/LexiGrid-client-linux-postgresql.zip) or clone this repository. Both include the application, deployment scripts, and product manuals.

This distribution is for a fresh installation on Linux with Python 3.11 or later and an empty PostgreSQL 16 database. Open [START_HERE.md](START_HERE.md) for the installation sequence, database account setup, and deployment checks.

## Product manuals

- [User Operations Guide](docs/distribution/LexiGrid_User_Guide.pdf)
- [Administrator and Deployment Guide](docs/distribution/LexiGrid_Administrator_Guide.pdf)
- [Document Extraction Guide](docs/distribution/LexiGrid_Document_Extraction_Guide.pdf)
- [Risk Reporting and Enterprise IRM](docs/distribution/LexiGrid_Risk_Reporting_and_Enterprise_IRM.pdf)
- [Compliance Audits and Read-only Identity Evidence](docs/distribution/LexiGrid_Compliance_Audit_Guide.pdf)
- [Full index of all 19 manuals](docs/MANUAL_INDEX.md)

## License

LexiGrid is free to use for purposes permitted by the [PolyForm Strict License 1.0.0](LICENSE.md). Commercial use, redistribution, and modification require separate permission. The license covers LexiGrid as distributed through this repository and the release ZIP. Third-party components remain subject to their own licenses.

Shahryar Jahangir · Aniza Inc.
