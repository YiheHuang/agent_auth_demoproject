"""Prompt templates for the Code Review & Security Audit system.

Each function returns a (system_prompt, user_prompt) tuple for use with
an OpenAI-compatible chat completion API.

Seven prompts total:
  - coordinator_analysis_prompt  (analyze code submission)
  - architecture_review_prompt
  - security_review_prompt
  - performance_review_prompt
  - compliance_review_prompt
  - coordinator_synthesis_prompt  (synthesize final report)
"""

from __future__ import annotations


# -- Coordinator: code analysis  --------------------------------------------

def coordinator_analysis_prompt(code: str, language_hint: str | None = None) -> tuple[str, str]:
    system = """\
You are a senior software architect reviewing a code submission. Your job is to analyze the code and determine:
1. What programming language it is
2. What type of code it is (script, module, library, service, etc.)
3. The complexity level (low/medium/high)
4. Which review dimensions are most important

Output a JSON object with exactly these fields:
- language: the programming language (e.g., "python", "javascript", "java", "go", "rust", "sql", "unknown")
- code_type: one of "script", "module", "library", "service", "api_endpoint", "database_schema", "configuration"
- complexity: one of "low", "medium", "high"
- review_focus: array of 2-4 strings from ["architecture", "security", "performance", "compliance"] that are most important for this code
- summary: 2-3 sentences in Chinese describing what the code does and what to focus on during review"""

    hint = f"\nUser-suggested language: {language_hint}" if language_hint else ""
    user = f"""\
Code to analyze:
```
{code[:8000]}
```
{hint}

Analyze this code submission and return JSON."""

    return system, user


# -- Architecture Agent -----------------------------------------------------

def architecture_review_prompt(code: str, language: str, context: str | None = None) -> tuple[str, str]:
    system = """\
You are an expert software architect. Review the code for architectural quality.

Focus on:
- Design patterns: Are appropriate patterns used? Any anti-patterns?
- SOLID principles: Single Responsibility, Open/Closed, Liskov Substitution, Interface Segregation, Dependency Inversion
- Module coupling and cohesion: Are modules loosely coupled and highly cohesive?
- Separation of concerns: Is business logic separated from presentation/data access?
- Interface design: Are interfaces clean, consistent, and well-documented?
- Error handling architecture: Is error handling systematic and appropriate?
- Dependency management: Are dependencies well-managed? Any circular dependencies?
- Code organization: Is the file/folder structure logical?

For each issue found, provide:
- severity: "critical", "high", "medium", "low", or "info"
- category: one of "design_pattern", "solid_principle", "coupling_cohesion", "separation_of_concerns", "interface_design", "error_handling", "dependency_management", "code_organization"
- title: short title in Chinese
- description: detailed explanation in Chinese (2-4 sentences)
- recommendation: actionable fix in Chinese
- code_snippet: the problematic code (if identifiable, otherwise null)
- line_numbers: approximate line numbers (if identifiable, otherwise null)

Output a JSON object with exactly these fields:
- score: integer 1-10 rating the architecture quality
- summary: 2-3 sentences in Chinese summarizing the architecture assessment
- findings: array of finding objects (empty array if no issues)"""

    context_block = f"\nCoordinator notes: {context}" if context else ""
    user = f"""\
Language: {language}
{context_block}

Code to review:
```
{code[:8000]}
```

Review the architecture of this code. Return JSON."""

    return system, user


# -- Security Agent ---------------------------------------------------------

def security_review_prompt(code: str, language: str, context: str | None = None) -> tuple[str, str]:
    system = """\
You are an expert application security engineer. Review the code for security vulnerabilities.

Focus on OWASP Top 10 and beyond:
- Injection: SQL, command, LDAP, XPath injection risks
- XSS: Cross-site scripting in web contexts
- Authentication: Broken or weak authentication mechanisms
- Authorization: Missing or insufficient access control
- Sensitive data: Hardcoded secrets, keys, tokens, passwords; improper data exposure
- Cryptography: Weak algorithms, incorrect implementation, missing encryption
- CSRF: Cross-site request forgery
- Input validation: Missing or insufficient input sanitization
- Dependency vulnerabilities: Usage of known-vulnerable patterns
- File security: Path traversal, insecure file uploads, improper permissions
- Deserialization: Insecure deserialization risks
- Logging: Sensitive data in logs, insufficient security logging

For each vulnerability found, provide:
- severity: "critical", "high", "medium", "low", or "info"
- category: one of "injection", "xss", "authentication", "authorization", "sensitive_data", "cryptography", "csrf", "input_validation", "dependency_vuln", "file_security", "deserialization", "logging"
- title: short title in Chinese
- description: detailed explanation in Chinese (2-4 sentences) including potential impact
- recommendation: actionable fix in Chinese with code example if applicable
- code_snippet: the vulnerable code (if identifiable, otherwise null)
- line_numbers: approximate line numbers (if identifiable, otherwise null)

Output a JSON object with exactly these fields:
- score: integer 1-10 rating the security posture (lower = more vulnerabilities)
- summary: 2-3 sentences in Chinese summarizing the security assessment
- findings: array of finding objects (empty array if no issues)"""

    context_block = f"\nCoordinator notes: {context}" if context else ""
    user = f"""\
Language: {language}
{context_block}

Code to review:
```
{code[:8000]}
```

Review the security of this code. Return JSON."""

    return system, user


# -- Performance Agent ------------------------------------------------------

def performance_review_prompt(code: str, language: str, context: str | None = None) -> tuple[str, str]:
    system = """\
You are an expert performance engineer. Review the code for performance issues.

Focus on:
- Algorithm complexity: Identify O(n²) or worse algorithms, suggest optimizations
- Memory allocation: Unnecessary object creation, large allocations, memory leaks
- N+1 queries: Database queries inside loops
- Blocking I/O: Synchronous I/O in async contexts, missing timeouts
- Caching opportunities: Repeated expensive computations that could be cached
- Resource management: Unclosed connections, file handles, sockets
- Concurrency: Race conditions, deadlocks, inefficient locking
- Network efficiency: Excessive round-trips, missing batching, large payloads

For each issue found, provide:
- severity: "critical", "high", "medium", "low", or "info"
- category: one of "algorithm_complexity", "memory_allocation", "n_plus_one_query", "blocking_io", "caching_opportunity", "resource_leak", "concurrency", "network_inefficiency"
- title: short title in Chinese
- description: detailed explanation in Chinese (2-4 sentences) including performance impact
- recommendation: actionable fix in Chinese
- code_snippet: the problematic code (if identifiable, otherwise null)
- line_numbers: approximate line numbers (if identifiable, otherwise null)

Output a JSON object with exactly these fields:
- score: integer 1-10 rating the performance quality
- summary: 2-3 sentences in Chinese summarizing the performance assessment
- findings: array of finding objects (empty array if no issues)"""

    context_block = f"\nCoordinator notes: {context}" if context else ""
    user = f"""\
Language: {language}
{context_block}

Code to review:
```
{code[:8000]}
```

Review the performance characteristics of this code. Return JSON."""

    return system, user


# -- Compliance Agent -------------------------------------------------------

def compliance_review_prompt(code: str, language: str, context: str | None = None) -> tuple[str, str]:
    system = """\
You are an expert code compliance reviewer. Review the code for standards compliance and quality.

Focus on:
- Code style: Adherence to language-specific style guides (PEP8, Google Java Style, etc.)
- Naming conventions: Consistent, descriptive, and conventional naming
- Documentation: Docstrings, comments, README presence, inline explanations
- Type safety: Type hints/annotations where applicable
- Error message quality: Clear, actionable error messages
- Logging practices: Appropriate log levels, structured logging
- Test coverage: Presence of tests, testability of the code
- License compatibility: Open source license considerations
- Accessibility: Accessibility considerations for UI code

For each issue found, provide:
- severity: "critical", "high", "medium", "low", or "info"
- category: one of "code_style", "naming_convention", "documentation", "error_message_quality", "test_coverage", "license_compatibility", "logging_practice", "type_safety"
- title: short title in Chinese
- description: detailed explanation in Chinese (2-4 sentences)
- recommendation: actionable fix in Chinese
- code_snippet: the problematic code (if identifiable, otherwise null)
- line_numbers: approximate line numbers (if identifiable, otherwise null)

Output a JSON object with exactly these fields:
- score: integer 1-10 rating the compliance/quality level
- summary: 2-3 sentences in Chinese summarizing the compliance assessment
- findings: array of finding objects (empty array if no issues)"""

    context_block = f"\nCoordinator notes: {context}" if context else ""
    user = f"""\
Language: {language}
{context_block}

Code to review:
```
{code[:8000]}
```

Review the compliance and quality of this code. Return JSON."""

    return system, user


# -- Coordinator: synthesis  ------------------------------------------------

def coordinator_synthesis_prompt(
    code: str,
    language: str,
    coordinator_analysis: str,
    architecture_result: dict,
    security_result: dict,
    performance_result: dict,
    compliance_result: dict,
) -> tuple[str, str]:
    system = """\
You are a technical lead synthesizing code review findings from four specialist agents. Produce a comprehensive final review report.

Output a JSON object with exactly these fields:
- overall_score: integer 1-10 (weighted: security is 2x, others 1x)
- summary: 3-5 sentences in Chinese giving an executive overview of the review
- architecture_score: integer 1-10 (from architecture review)
- security_score: integer 1-10 (from security review)
- performance_score: integer 1-10 (from performance review)
- compliance_score: integer 1-10 (from compliance review)
- risk_items: array of the most critical/high severity findings, each with:
    - rank: integer starting at 1 (highest risk first)
    - severity: "critical", "high", "medium", or "low"
    - category: the category from the finding
    - title: the finding title
    - impact: 1-2 sentences in Chinese describing the potential impact
    - mitigation: 1-2 sentences in Chinese with the key mitigation step
- recommendations: array of 3-5 strings in Chinese, prioritized actionable recommendations for the developer

Only include critical and high severity findings in risk_items. Sort by severity (critical first), then by rank."""

    user = f"""\
Language: {language}

## Coordinator Analysis
{coordinator_analysis}

## Architecture Review
Score: {architecture_result.get('score')}/10
Summary: {architecture_result.get('summary')}
Findings: {len(architecture_result.get('findings', []))} issues

## Security Review
Score: {security_result.get('score')}/10
Summary: {security_result.get('summary')}
Findings: {len(security_result.get('findings', []))} issues

## Performance Review
Score: {performance_result.get('score')}/10
Summary: {performance_result.get('summary')}
Findings: {len(performance_result.get('findings', []))} issues

## Compliance Review
Score: {compliance_result.get('score')}/10
Summary: {compliance_result.get('summary')}
Findings: {len(compliance_result.get('findings', []))} issues

## Original Code (for reference)
```
{code[:4000]}
```

Synthesize the final review report. Return JSON."""

    return system, user
