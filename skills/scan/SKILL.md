---
name: scan
description: Verify AI-generated code with Acutis PCST contracts. Use before showing or writing security-relevant code, when an Acutis hook reminds you to scan, or when scan_code returns BLOCK_INCOMPLETE/T-WITNESS. Teaches sources, sinks, transforms, SafeOutput, arg roles, policy attributes, and witness-path reasoning for XSS, SQLi, command injection, path traversal, SSRF, redirects, headers/logs, LDAP/XPath/NoSQL, CSV, dynamic import, reflection, code evaluation, deserialization, signature verification, cleartext transmission, format strings, SSTI, XML injection, and argument injection.
---

# Security Scan with Acutis

Call the Acutis `scan_code` MCP tool with your proposed code output and a PCST contract **before showing the code in chat or writing it to a file**. The MCP server name contains "acutis" (e.g. `user-acutis` or `acutis`). Acutis verifies generated code, never a file. The PostToolUse hook fires after a write as a fallback nudge, but the canonical invocation point is *pre-write*. Continue until the decision is `ALLOW`.

## Languages and Scan Units

- `language` accepts `python`, `javascript`, `typescript`, and `java`. Submit TypeScript as `typescript`: TS syntax under `javascript` fails closed with a parse error. Submit TSX as `typescript` too (it fails closed rather than under-verifying JSX sinks).
- Scan the real diff even when an edit is type-only (interfaces, type aliases, annotations, `as` casts). Declarations-only code has no call sites, so an honest minimal contract reaches ALLOW immediately. Never scan a fabricated "representative" snippet in place of the code you actually wrote; a verdict attached to invented code is worse than no verdict.
- The unit of verification is the code you are about to emit this turn. For a multi-fragment change-set, concatenate the fragments (blank line between them) into one submission. For merge or rebase conflict resolutions, scan the newly authored lines plus enough surrounding code to keep each source-to-transform-to-sink flow visible, not the whole pre-existing file.

## Workflow

1. Identify user-controlled sources: request parameters, body fields, route params, CLI args, environment values, uploaded file names, external JSON, or function parameters representing user input.
2. Identify every security boundary reached by that data: HTML, SQL, shell command, file path, outbound URL, network transmission, eval/deserialization, redirect, header, log, LDAP/XPath/NoSQL, CSV cell, dynamic import, reflection, signed-payload use, format-string template, template renderer, XML DOM builder, or argv exec.
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

<examples>

<example name="flask-html-response">
<description>Flask HTML response — XSS risk, sanitized via `escape`.</description>
<contract>
```json
{
  "sources": ["request.args.get"],
  "sinks": [{ "name": "render_template_string", "category": "HTMLOutput" }],
  "transforms": [{ "name": "escape", "effect": "EscapesHTML" }]
}
```
</contract>
</example>

<example name="express-wrapper-pattern">
<description>Express.js with a helper that builds HTML and an outer sender. The inner builder is the real HTMLOutput sink; the sender is SafeOutput because it just forwards the already-built string.</description>
<code>
```js
res.send(renderPage(escapeHtml(req.query.msg)))
```
</code>
<contract>
```json
{
  "sources": ["req.query"],
  "sinks": [
    { "name": "renderPage", "category": "HTMLOutput" },
    { "name": "res.send", "category": "SafeOutput" }
  ],
  "transforms": [{ "name": "escapeHtml", "effect": "EscapesHTML" }]
}
```
</contract>
</example>

<example name="flask-json-endpoint">
<description>Flask JSON endpoint — no XSS/SQLi vector, `jsonify` does not interpret values as HTML.</description>
<contract>
```json
{
  "sources": ["request.args.get"],
  "sinks": [{ "name": "jsonify", "category": "SafeOutput" }],
  "transforms": []
}
```
</contract>
</example>

<example name="sql-parameterized">
<description>SQL query with parameter binding — `cursor.execute` is both the SQL sink and the parameterizing transform.</description>
<contract>
```json
{
  "sources": ["request.args.get"],
  "sinks": [{ "name": "cursor.execute", "category": "SQLQuery" }],
  "transforms": [{ "name": "cursor.execute", "effect": "ParameterizesSQL" }]
}
```
</contract>
</example>

<example name="dynamic-order-by-allowlist">
<description>Dynamic ORDER BY with allowlist validation. The scanner cannot recognize an if-guard as a transform; wrap the validation in a helper call so the source → transform → sink path is explicit.</description>
<code>
```python
safe_order = validate_order_by(request.args.get("sort"))
cursor.execute(build_query(safe_order))
```
</code>
<contract>
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
</contract>
</example>

</examples>

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
| Improper signature verification (CWE-347) | `SignedPayloadUse` | `VerifiesSignature` |
| Cleartext transmission (CWE-319) | `NetworkTransmission` | `EnforcesTransportSecurity` |
| Format string injection (CWE-134) | `FormatString` (arg-role-gated) | none; declare the user value as `FormatArg`, never `FormatTemplate` |
| Server-side template injection (CWE-1336/94) | `TemplateRenderer` (arg-role-gated) | none; pass user input as `TemplateData` render context, never `TemplateSource` |
| XML DOM / content injection (CWE-91) | `XMLDOMBuilder` (arg-role-gated) | none; declare user input as `Content` (text/attribute value), never `Structural` |
| Argument injection (CWE-88) | `ArgvExec` (arg-role-gated) | none; keep user input in `Content` operand positions, never `Structural` option/subcommand slots |

### Property-Preserving String Operations

Chained string helpers that neither add nor remove danger (`trim`, `slice`, `toLowerCase`, `normalize`, `String(...)`) re-widen to unknown under Zero Trust when left undeclared. This is the most common cause of a T-RECURSIVE-BODY failure on an otherwise-correct sanitizer body: the sanitizing step works, then a trailing `.trim()` resets the result to untrusted. Declare such calls with the `PreservesProperties` effect:

```json
{ "name": "trim", "effect": "PreservesProperties" }
```

Naming rules for transforms:

- A bare method name (`trim`, `replace`, `test`) covers that method on every receiver; `value.replace` covers only calls on `value`. Prefer the bare name when the same helper method appears on several receivers.
- Hoist inline regex literals to a named constant before calling `.test(...)`: an inline literal receiver produces an unstable clause name derived from the regex source text.

## Arg-Role-Gated Sinks

Four categories (`FormatString`, `TemplateRenderer`, `XMLDOMBuilder`, `ArgvExec`) are dangerous only in specific argument positions. The same tainted value is safe as data but dangerous as structure, and only you know which role each argument plays. Declare it with `arg_roles`, keyed by 0-based argument index:

```json
{
  "sources": ["user_msg"],
  "sinks": [
    {
      "name": "logger.info",
      "category": "FormatString",
      "arg_roles": { "0": "FormatTemplate", "1": "FormatArg" }
    }
  ],
  "transforms": []
}
```

Role pairs (danger role first, safe counterpart second):

- `FormatString`: `FormatTemplate` / `FormatArg`
- `TemplateRenderer`: `TemplateSource` / `TemplateData`
- `XMLDOMBuilder`: `Structural` / `Content`
- `ArgvExec`: `Structural` / `Content` (per argv element)

These are absorbing on the danger role: no transform makes a user-controlled format template, template source, or structural position safe. The fix is always to move user input to the safe role (interpolate as a format arg, pass as render context, write as text content, keep as an operand). Tainted data in the safe role does not trip the constraint. Declare roles honestly; do not mark a template-source argument as `TemplateData` to force an ALLOW.

### Optional Content Exemptions (FileSystemPath, OutboundHTTPRequest, NetworkTransmission, HTTPRedirect)

These four categories check EVERY argument by default (write(path, contents) flags tainted contents too, since every argument is inspected). When an argument is pure data the sink never interprets as a path, URL, endpoint, or redirect target, declare its 0-based index `Content` to exempt it:

```json
{
  "sources": ["userData"],
  "sinks": [
    {
      "name": "Bun.write",
      "category": "FileSystemPath",
      "arg_roles": { "1": "Content" }
    }
  ],
  "transforms": []
}
```

Rules: omitting `arg_roles` checks every argument (the strictest default); every UNDECLARED index stays checked, so a partial map cannot silence the locator slot; each exemption is recorded in the proof bundle as a caller-trusted assumption. Never declare the locator argument `Content`, and never recategorize one of these sinks `SafeOutput` to clear a violation; if the locator is genuinely tainted, sanitize it with a transform (`NormalizesPath`, `ValidatesURLHost`, `EnforcesTransportSecurity`, `ValidatesRedirectTarget`).

## Trusted Deployment-Config Sources

A value that is operator-controlled deployment configuration resolved server-side (an interpreter path from the server's env-config module, a fixed internal service host) is not request data, and declaring it a plain source forces a false BLOCK with no honest exit. Declare it a trusted source instead:

```json
{
  "sources": [
    {
      "name": "py_bin",
      "kind": "param",
      "trust": "deployment_config",
      "trust_reason": "resolved from the server env-config module at deploy time; not request data"
    }
  ],
  "sinks": [{ "name": "spawn", "category": "CommandExecution" }],
  "transforms": []
}
```

The name then types as safe at direct reads; any concatenation or reassignment involving untrusted data re-widens and still blocks, and the declaration (with its reason) is recorded in the proof bundle as a caller-trusted assumption. `trust_reason` is required. Scope this honestly: request-derived values, user uploads, and anything a client can influence are NEVER deployment config.

## Signed Payloads and Cleartext Transport

`SignedPayloadUse` (CWE-347) is an absorbing sink for acting on JWT / webhook / token payloads: user-controlled payload data must pass through a `VerifiesSignature` transform before anything trusts it.

```json
{
  "sources": ["jwt_payload"],
  "sinks": [{ "name": "grant_access", "category": "SignedPayloadUse" }],
  "transforms": [{ "name": "verify_signature", "effect": "VerifiesSignature" }]
}
```

`NetworkTransmission` (CWE-319) covers outbound transmission where the endpoint's transport security is unconfirmed (broader than HTTP: ftp, smtp, ws, raw sockets). It is deliberately separate from `OutboundHTTPRequest` (SSRF); pick the category matching the concern at that sink. A validation step that guarantees https (or rejects otherwise) is declared `EnforcesTransportSecurity`:

```json
{
  "sources": ["endpoint_url"],
  "sinks": [{ "name": "http_post", "category": "NetworkTransmission" }],
  "transforms": [{ "name": "ensure_https", "effect": "EnforcesTransportSecurity" }]
}
```

A hardcoded literal `http://` URL with no taint is handled by the policy lane (a `transport:cleartext` forbid atom), not by this category.

## Policy Lane (Customer-Gated CWEs)

Deployments can install a customer `SecurityPolicy` (forbid atoms plus numeric ceilings, resolved server-side; never part of your contract). This gates CWE-326/327/329/760 (weak crypto), CWE-732 (permissions), and CWE-377 (insecure temp files). Your job is to declare honest `attributes` (lowercase `key:value` atoms) on sinks and transforms that have policy-relevant characteristics:

```json
{
  "sources": [],
  "sinks": [
    { "name": "hashlib.md5", "category": "SafeOutput", "attributes": ["digest:md5"] },
    { "name": "os.chmod", "category": "SafeOutput", "attributes": ["file-mode:0600"] }
  ],
  "transforms": []
}
```

If a declared attribute matches the deployment's forbidden set, the scan returns `BLOCK_VIOLATION` with a `policy_violation` finding; fix the code to use a compliant primitive (e.g. SHA-256 instead of MD5, mode 0600 instead of 0777) and rescan. With no policy installed, attributes are inert. In `strict_attributes` deployments, omitting `attributes` entirely on a declaration causes `BLOCK_INCOMPLETE`; declare `"attributes": []` to attest there are no policy-relevant characteristics.

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

**"T-RECURSIVE-BODY: ... its submitted body does not justify that effect"**
The declared effect could not be re-derived from the submitted body. Usual causes:

1. A trailing unannotated call (`.trim()`, `.slice()`, `.normalize()`) after the sanitizing step re-widens the return value; declare it `PreservesProperties` (see Property-Preserving String Operations above).
2. The body genuinely does not implement the declared effect; narrow the effect or fix the implementation.

**`BLOCK_VIOLATION`**
The contract is good enough to prove a vulnerability. Fix the code, then scan again. Do not weaken the boundary to `SafeOutput` unless the function truly does not interpret the input in that dangerous context.

## Key Principles

1. **Think in witness paths, but omit `witnesses`** — Acutis auto-infers them.
2. **Transforms are function calls only** — allowlists, set checks, and if-guards are not transforms unless wrapped in a helper call.
3. **SafeOutput is for non-interpreting boundaries** — logging, JSON serialization, response senders, and pass-through wrappers may be SafeOutput when they do not interpret the value.
4. **Wrapper pattern** — the inner function that builds/interprets HTML, SQL, command strings, paths, URLs, code, etc. is the real sink. The outer function that just forwards the result is usually SafeOutput.
5. **Keep contracts honest** — never mark a dangerous interpreter as SafeOutput just to get `ALLOW`.
6. **Scan until ALLOW** — `BLOCK_INCOMPLETE` means fix the contract or code shape; `BLOCK_VIOLATION` means fix the code.
