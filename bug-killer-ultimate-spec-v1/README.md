# Bug Killer: Ultimate Security Discovery & Repair Specification

**Version:** 1.0.0 (architecture specification)  
**Date:** 2026-10-25  
**Owner:** Mamdouh Aboammar  
**Repository:** https://github.com/imMamdouhaboammar/bug-killer  
**Baseline:** `master` following merged PR #25, merge commit `636887a76dc1654d51005af6210c605b7e556ecb`  
**Status:** Proposed architecture, implementation contracts, and execution plan. **Not a claim that these capabilities already exist.**

## الملخص التنفيذي

هدف Bug Killer أن يساعد المطورين وفرق الأمن والـvibe coders في ثلاث مهمات:

1. اكتشاف وإصلاح الثغرات المعروفة المنشورة بالفعل، سواء داخل الكود أو الاعتماديات.
2. اكتشاف الأخطاء والأنماط الأمنية الشائعة، ومنها كتالوج القواعد الـ373، وإصلاحها بعد التحقق.
3. البحث المنهجي عن ثغرات غير معروفة أو غير مبلغ عنها، وبناء دليل قابل لإعادة الإنتاج، ثم المساعدة في الإبلاغ المسؤول عنها.

**القرار:** نحتفظ بـRust Core، وندمج Tree-sitter وast-grep في مسار التحليل الأساسي، مع Joern كـDeep Analysis Sidecar، وSemgrep CE كـAdapter اختياري، وCodeQL كـAdapter مرخص حسب الأهلية. نطور OSV الحالي، ونضيف Evidence Gate وResearch Sandbox وRemediation Verification. لا نعيد بناء AST Parser من الصفر.

**حدود الوعد:** لا يمكن اعتبار اكتمال تسجيل 373 قاعدة إثباتًا لاكتشاف جميع الثغرات. يعرض النظام أدلة التغطية ودرجة اليقين وما لم يُفحص. لا يطلق تلقائيًا ادعاءات Zero-Day أو تقارير ثغرات عامة.

## Use this ZIP

Read in the following order. Each document is independently usable and cross-referenced.

| File | Purpose |
|---|---|
| [00-VISION-AND-SCOPE.md](00-VISION-AND-SCOPE.md) | Mission, users, product modes, success criteria, non-goals |
| [01-CURRENT-STATE-AND-GAPS.md](01-CURRENT-STATE-AND-GAPS.md) | Source-grounded baseline, existing modules and issue dependencies |
| [02-ARCHITECTURE-AND-ADRS.md](02-ARCHITECTURE-AND-ADRS.md) | Logical design, engine boundaries, versioning and architecture decisions |
| [03-KNOWN-VULNERABILITY-INTELLIGENCE.md](03-KNOWN-VULNERABILITY-INTELLIGENCE.md) | OSV/GHSA/CVE ingestion, SBOM, exact affectedness and fixes |
| [04-STATIC-ANALYSIS-AND-CATALOG.md](04-STATIC-ANALYSIS-AND-CATALOG.md) | Tree-sitter, ast-grep, taint, 373-rule validation and parity migration |
| [05-NOVEL-VULNERABILITY-HUNTER.md](05-NOVEL-VULNERABILITY-HUNTER.md) | Research hypotheses, bounded fuzzing, reproducibility, discovery lifecycle |
| [06-EVIDENCE-AND-VERIFICATION.md](06-EVIDENCE-AND-VERIFICATION.md) | Typed receipts, coverage, certainty, metrics and security gates |
| [07-REMEDIATION-AND-TRUST.md](07-REMEDIATION-AND-TRUST.md) | Permission boundaries, safe patches, approvals, backups and rollback |
| [08-CLI-MCP-AND-UX.md](08-CLI-MCP-AND-UX.md) | Existing vs proposed commands, MCP, JSON output and persona journeys |
| [09-INTEGRATION-DECISIONS.md](09-INTEGRATION-DECISIONS.md) | All evaluated projects, licensing, adapters, build-vs-buy decisions |
| [10-IMPLEMENTATION-PLAN.md](10-IMPLEMENTATION-PLAN.md) | Dependency ordered work packages, PR contracts, milestones |
| [11-TESTING-BENCHMARKS-AND-RELEASE.md](11-TESTING-BENCHMARKS-AND-RELEASE.md) | Red/green tests, quality benchmarks, CI matrices and release gates |
| [12-DISCLOSURE-AND-GOVERNANCE.md](12-DISCLOSURE-AND-GOVERNANCE.md) | Private reporting, retention, provenance, security feeds and operations |
| [13-OPEN-DECISIONS-AND-RISKS.md](13-OPEN-DECISIONS-AND-RISKS.md) | Explicit decisions, uncertainties, risks and exit criteria |
| [AGENT-EXECUTION-BRIEF.md](AGENT-EXECUTION-BRIEF.md) | Ready-to-use brief for coding agents; read after architecture |
| [schemas/](schemas/) | Versioned JSON Schemas for analyzer requests/results, findings, coverage and repairs |
| [examples/](examples/) | Example policy and research-candidate payload |
| [TRACEABILITY.csv](TRACEABILITY.csv) | Requirement-to-work-package-to-test mapping |
| [scripts/validate-spec.sh](scripts/validate-spec.sh) | Offline packaging and syntax checks for this specification |

## Baseline and evidence policy

- This specification was constructed from an inspected local checkout reflecting the PR #25 merged source tree, repository AGENTS.md, existing CLI/types, and the open issue tracker as checked on 2026-10-25.
- GitHub issues may move. **Reconfirm every issue and code assertion against current master before writing an implementation PR.**
- Intended work is strictly defensive and authorized: no public exploit automation, attacks on third-party live services, credential extraction, or unapproved external vulnerability publication.
- Snippets, schemas, config paths and commands marked **PROPOSED** are not guaranteed to exist in the present code.
- Dependencies must be pinned, license-scanned, reproducibly built and independently evaluated before adoption.

## Delivery definition

The project is ready to claim each capability only after the corresponding contractual tests in Section 11 pass, telemetry is truthful, and a release can be reproduced. **A successful build is not a security proof.**

### Verify the spec archive

Run `bash scripts/validate-spec.sh` from this directory. This validates JSON syntax, the expected examples, markdown code-fence balance and required files. It is a **packaging smoke test**, not a full JSON Schema validator or evidence that any proposed engine is implemented.
