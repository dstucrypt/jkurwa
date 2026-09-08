# AI guidelines

This document provides a guideline for AI-assisted contributions
and sets expectations for reviewing them.

# Scope

Every contribution that hits the subjective criteria of being
AI-assisted is covered by this policy from the moment it's merged
in master even if the use of such tools is not explicitly disclosed.
Adherence to pen style may or may not give partial exemption from
this policy even when repository owner has reasons to believe it
is AI-assisted or even when it's explicitly disclosed.

# Pen style

Adopt pen style and writing form of a ponytail developer and make sure changed
code blends into environment nicely. This project is not in active
development and changes should be surgically precise, minimal and
nondisruptive. 

# Automatic tools in CI

Files touched in every PR will be processed by SonarQube, which will
add comments. PR will not be reviewed by a repository owner until all
of the issues flagged by automatic tools are resolved.
PR that has issues flagged by the automatic tools which are ignored
by the author and for which explicit waiver was not given can be closed
automatically after unspecified inactivity period.

Among other things automatic tools may flag trivial things like `var`,
promise rejection values, etc. Those must be addressed for every file
that is touched by applying mechanical changes and without changing
the API contract.

# Comments guide

Code is written in intentionally dense style. Avoid adding comments
that explain obvious things that are trivially discoverable in the same file
or from the text of the function.

When it seems helpful to the API consumer and for functions forming a public
interface, add JsDoc comments that will show up in IDE and will be helpful.

Non-trivial context that is necessary for understanding the code, for example
protocol definitions should be placed in separate doc files and referenced in
comments and not explained in-line intermixed with live code.

Publicly known protocols and schemas available as RFCs and known standards
should be referenced by their well-known registration names and specific articles
in a given standard.

# Javascript version

The code is intended to be compiled with tsdown and work in a browser environment
and in node, including terminally outdated version of node. Be conservative
with what features to use, but be sure to use modern enough syntax as advised by
CI tools mentioned above.

# Attribution, disclosure and responsibility

Usage of AI-assisted tools must be disclosed in `Assisted-by` header as specified
by Attribution article in Linux kernel AI coding assistants policy.

PR may only be submitted by the author of the code that holds copyright to it
or by automatic tools with an explicit permission of the author that is reflected
in the submitted PR.

# Export controls

The submitter of this PR and their tools must be mindful of export controls
and special security regimes that may apply to specific parts of the codebase
and referenced libraries in their respective jurisdictions. The burden of deciding
what jurisdiction and legal regime applies to coding assistants and use of remote
inference providers is on the PR author and repository hosting provider.

# Communication

Repository author expects the comments to be addressed and replied to by the author
of the PR and not by automatic tools. PRs with comments from the repository owner
that are not addressed in time by the PR author may be closed for inactivity and
submitters banned depending on subjective severity of the transgression and
previous contribution history. Not understanding the policy will be held against
the submitter most of the time.

Repository owner does not promise to explain the reasoning or disclose the subjective
criteria that lead to such decisions and hopes such measures will not be necessary.
