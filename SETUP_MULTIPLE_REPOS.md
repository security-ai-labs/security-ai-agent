# Security AI Agent - Multi-Repo Setup Guide

## Option 1: Reusable Workflow Setup

This document explains how to use the Security AI Agent in multiple repositories.

### Prerequisites

- Access to `security-ai-labs/security-ai-agent` repository
- Organization or personal GitHub account
- Repositories where you want to add security reviews

### Step 1: Ensure Central Agent Repo is Ready

In `security-ai-labs/security-ai-agent`:

1. ✅ Verify `.github/workflows/security-review-reusable.yml` exists
2. ✅ Verify all agent files exist:
   - `main.py`
   - `ai_analyzer.py`
   - `github_pr_commenter.py`
   - `security_rules.py`
   - `requirements.txt`
   - `config.yaml`

### Step 2: Set Up New Repository

For each repository where you want to use the agent:

#### 2.1 Create Workflow File

Create `.github/workflows/security.yml` in the target repository:

```yaml
name: Security Review

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  security:
    uses: security-ai-labs/security-ai-agent/.github/workflows/security-review-reusable.yml@main
    secrets:
      OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}