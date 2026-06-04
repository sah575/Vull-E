# Vull-E RAG Source Priority And Hallucination Controls

Use this document to guide how Vull-E should reason over retrieved context.

## Source Priority

1. Jira ticket and linked Confluence pages describe the specific change.
2. Internal role matrices, API documentation, security standards, and past
   findings describe bank-specific rules.
3. OWASP ASVS, WSTG, API Security, and Cheat Sheet notes describe general
   security expectations and test techniques.
4. General examples are hints only and must not override project-specific rules.

## Reasoning Rules

- Do not claim a vulnerability exists only because OWASP context was retrieved.
- Use OWASP context to create hypotheses and test ideas.
- Use Jira, Confluence, internal docs, and evidence to increase confidence.
- If required business rules are missing, ask for missing information instead of
  inventing the rule.
- Separate risk hypothesis from validated finding.
- Include source names when a recommendation depends on retrieved context.

## Confidence Guidance

High confidence:
- Ticket mentions concrete endpoint or object ID.
- Role or scope rule exists in Jira, Confluence, or internal docs.
- RAG context matches the same object type and workflow.

Medium confidence:
- Ticket has strong risk signals but lacks endpoint or role matrix detail.
- OWASP context applies but internal rule is missing.

Low confidence:
- Only broad keywords match.
- No endpoint, object, role, state transition, or data classification is known.

## Output Guardrails

- Prefer "test whether" instead of "is vulnerable" before validation.
- Avoid exploit payloads unless the workflow is explicitly a safe manual test
  plan.
- Flag state-changing tests as requiring approval.
- Do not recommend tests outside the allowed scope.

## Vull-E Retrieval Keywords

source priority, hallucination, confidence, validated finding, risk hypothesis,
missing information, evidence, source names, guardrails

