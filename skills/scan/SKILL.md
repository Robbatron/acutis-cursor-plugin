---
name: scan
description: Verify AI-generated code with Acutis PCST contracts. Use before showing or writing security-relevant code, when an Acutis hook reminds you to scan, or when scan_code returns BLOCK_INCOMPLETE/T-WITNESS. Teaches sources, sinks, transforms, SafeOutput, and witness-path reasoning for XSS, SQLi, command injection, path traversal, SSRF, redirects, headers/logs, LDAP/XPath/NoSQL, CSV, dynamic import, reflection, code evaluation, and deserialization.
---

# Security Scan with Acutis

Call the Acutis `scan_code` MCP tool with your proposed code output and a PCST contract **before showing the code in chat or writing it to a file**. The MCP server name contains "acutis" (e.g. `user-acutis` or `acutis`). Acutis verifies generated code, never a file. The PostToolUse hook fires after a write as a fallback nudge, but the canonical invocation point is *pre-write*. Continue until the decision is `ALLOW`.

## Workflow

1. Identify user-controlled sources: request parameters, body fields, route params, CLI args, environment values, uploaded file names, external JSON, or function parameters representing user input.
2. Identify every security boundary reached by that data: HTML, SQL, shell command, file path, outbound URL, eval/deserialization, redirect, header, log, LDAP/XPath/NoSQL, CSV cell, dynamic import, or reflection.
3. Mentally trace a witness path for each risky flow: `source -> transform(s) -> sink`. Use this trace to build the contract.
4. Declare all source functions/variables in `sources`.
5. Declare dangerous boundaries in `sinks` with the correct `category`.
6. Declare only actual sanitizer/helper function calls in `transforms`.
7. Add non-security pass-through calls as `SafeOutput` sinks when the verifier asks for missing coverage.
8. Omit `witnesses`. Acutis auto-infers them from the code and contract. If witness inference fails, fix the contract or reshape the code path; do not invent manual witness IDs.

## PCST Contract Shape

Use the minimal shape:

```json
{
  "sources": ["request.args.get"],
  "sinks": [
    { "name": "render_html", "category": "HTMLOutput" }
  ],
  "transforms": [
    { "name": "escape_html", "effect": "EscapesHTML" }
  ]
}
```

The scanner accepts `transforms` as shorthand for `transformations`, and `effect` as shorthand for `transformation_effect`.

## Witness-Path Reasoning

Witnesses are formal flow paths. You normally **do not write them in the contract**, but you should reason as if you were writing one:

```text
request.args.get -> escape_html -> render_html
```

That means the contract needs:

```json
{
  "sources": ["request.args.get"],
  "sinks": [{ "name": "render_html", "category": "HTMLOutput" }],
  "transforms": [{ "name": "escape_html", "effect": "EscapesHTML" }]
}
```

If the code hides the flow inside f-strings, string concatenation across variables, fluent chains, or control-flow-only validation, Acutis may return `BLOCK_INCOMPLETE` with `T-WITNESS`. Prefer code shapes where user input reaches sinks through explicit function calls:

```python
# Easier for Acutis to verify
safe = escape_shell(user_input)
return execute_command(safe)
```

Rather than:

```python
# Harder to witness-infer
return os.popen(f"ping -c 1 {user_input}").read()
```

For `T-WITNESS`, do not manually add witness IDs unless the tool explicitly asks for them. Usually fix one of these:

- Missing helper declaration: add the helper as a sink (`HTMLOutput`, `SQLQuery`, etc.) or `SafeOutput`.
- Hidden flow: refactor so the source, transform, and sink are separate calls.
- Wrong source name: use the exact source symbol or function the code calls.
- Wrapper pattern: mark the inner builder/interpreter as the real boundary and the outer sender as `SafeOutput`.

## Contract Examples

**Flask HTML response** (XSS risk — sanitized):
```json
{
  "sources": ["request.args.get"],
  "sinks": [{ "name": "render_template_string", "category": "HTMLOutput" }],
  "transforms": [{ "name": "escape", "effect": "EscapesHTML" }]
}
```

**Express.js with helper function** (wrapper pattern):
```json
# Code: res.send(renderPage(escapeHtml(req.query.msg)))
# renderPage builds HTML → it's the real sink (HTMLOutput)
# res.send just passes the string through → SafeOutput
{
  "sources": ["req.query"],
  "sinks": [
    { "name": "renderPage", "category": "HTMLOutput" },
    { "name": "res.send", "category": "SafeOutput" }
  ],
  "transforms": [{ "name": "escapeHtml", "effect": "EscapesHTML" }]
}
```

**Flask JSON endpoint** (safe — no XSS/SQLi vector):
```json
{
  "sources": ["request.args.get"],
  "sinks": [{ "name": "jsonify", "category": "SafeOutput" }],
  "transforms": []
}
```

**SQL query with parameterization**:
```json
{
  "sources": ["request.args.get"],
  "sinks": [{ "name": "cursor.execute", "category": "SQLQuery" }],
  "transforms": [{ "name": "cursor.execute", "effect": "ParameterizesSQL" }]
}
```

**Dynamic ORDER BY with allowlist guard**:
The scanner cannot rely on an if-guard as a transform. Prefer a helper call:

```python
safe_order = validate_order_by(request.args.get("sort"))
cursor.execute(build_query(safe_order))
```

```json
{
  "sources": ["request.args.get"],
  "sinks": [
    { "name": "build_query", "category": "SQLQuery" },
    { "name": "cursor.execute", "category": "SafeOutput" }
  ],
  "transforms": [{ "name": "validate_order_by", "effect": "ParameterizesSQL" }]
}
```

## Boundary Categories and Transforms

| Vulnerability | Sink category | Transform effects |
| --- | --- | --- |
| XSS / HTML injection | `HTMLOutput`, `JSONOutput`, `URLSink` | `EscapesHTML`, `ValidatesURLProtocol`, `EncodesURL`, `DecodesURL` |
| SQL injection | `SQLQuery` | `EscapesSQL`, `ParameterizesSQL` |
| OS command injection | `CommandExecution` | `EscapesShell`, `ValidatesCommand` |
| Path traversal | `FileSystemPath` | `NormalizesPath`, `ValidatesPath` |
| SSRF | `OutboundHTTPRequest` | `ValidatesURLHost`, `ResolvesURL` |
| Code injection | `CodeEvaluation` | none preferred; use trusted literals or strict validation |
| Unsafe deserialization | `UnsafeDeserialization` | none preferred; avoid deserializing user input |
| Open redirect | `HTTPRedirect` | `ValidatesRedirectTarget` |
| HTTP response splitting / log injection | `HTTPHeader`, `LogOutput` | `StripsNewlines`, `EscapesCRLF` |
| LDAP injection | `LDAPQuery` | `EscapesLDAP` |
| XPath injection | `XPathQuery` | `EscapesXPath` |
| NoSQL injection | `NoSQLQuery` | `ParameterizesNoSQL`, `EscapesNoSQL` |
| CSV formula injection | `CSVCell` | `EscapesCSVFormula` |
| Dynamic import | `DynamicImport` | `ValidatesModuleName` |
| Unsafe reflection | `Reflection` | `ValidatesReflectionTarget` |

## Troubleshooting BLOCK_INCOMPLETE

**"missing coverage for X"**
Add `X` to the contract. Use `SafeOutput` for functions that do not interpret their input as HTML, SQL, shell, path, URL, code, headers, logs, etc.

**"T-WITNESS: missing witness coverage for callsite(s)"**
Do not add witnesses manually. Fix the flow or declarations:

1. Add missing helpers as sinks or `SafeOutput`.
2. Make the source -> transform -> sink path explicit through function calls.
3. Avoid chained calls for the dangerous boundary if the verifier cannot infer a witness.
4. Verify source and sink names exactly match observed call names.

**"T-CONSISTENT (reverse): parser observed HTMLOutput at X"**
The scanner detected an HTML sink you didn't declare. Add it to your contract.

**`BLOCK_VIOLATION`**
The contract is good enough to prove a vulnerability. Fix the code, then scan again. Do not weaken the boundary to `SafeOutput` unless the function truly does not interpret the input in that dangerous context.

## Key Principles

1. **Think in witness paths, but omit `witnesses`** — Acutis auto-infers them.
2. **Transforms are function calls only** — allowlists, set checks, and if-guards are not transforms unless wrapped in a helper call.
3. **SafeOutput is for non-interpreting boundaries** — logging, JSON serialization, response senders, and pass-through wrappers may be SafeOutput when they do not interpret the value.
4. **Wrapper pattern** — the inner function that builds/interprets HTML, SQL, command strings, paths, URLs, code, etc. is the real sink. The outer function that just forwards the result is usually SafeOutput.
5. **Keep contracts honest** — never mark a dangerous interpreter as SafeOutput just to get `ALLOW`.
6. **Scan until ALLOW** — `BLOCK_INCOMPLETE` means fix the contract or code shape; `BLOCK_VIOLATION` means fix the code.
