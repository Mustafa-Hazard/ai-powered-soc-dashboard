# Phase 0 — AWS Account Setup

## Goal
Set up a properly secured AWS account from scratch, following least-privilege and
account-security best practices before touching any infrastructure.

## Steps Taken

1. **Created AWS account** using the Free Plan (no charges until explicit upgrade).
2. **Enabled MFA on the root account** using an authenticator app — root is never used
   for daily work after this point.
3. **Created an IAM user** (`mustafa-soc-lab`) for all day-to-day console access,
   attached with `AdministratorAccess` for lab flexibility (would be scoped tighter
   in a production environment).
4. **Enabled IAM billing access** at the root/account level, since IAM users cannot
   view billing information by default — this is a separate opt-in setting AWS
   requires for security reasons.
5. **Set up a Zero-Spend Budget** in AWS Budgets to get an email alert on any charge,
   however small — a safety net against accidentally exceeding free tier limits.

## Decisions & Notes

- **Region:** Intended to use Asia Pacific (Mumbai, `ap-south-1`) for lower latency
  from Pakistan. This region required manual opt-in activation (some AWS regions are
  disabled by default for new accounts). Activation took a short while to propagate.
- **IAM permission scope:** Chose broad `AdministratorAccess` deliberately for this
  solo lab account, to avoid friction while still learning which AWS services are
  needed. Noted as a explicit, defensible tradeoff for interviews — not an oversight.

## Lessons Learned

- New AWS accounts don't have access to all regions by default — some (like Mumbai)
  require manual enabling under Account → AWS Regions, and can take time to activate.
- IAM users need billing access explicitly granted at the account level; it is not
  covered by `AdministratorAccess`.
