# Glivela Agent Rules

## Petauron team: alpha-stage MVP delivery

- Prioritize a usable, end-to-end implementation of the approved requirement. Finish existing work and fix confirmed problems before proposing additional features, abstractions or refactors. One owner handles each feature end to end; do not split frontend/backend ownership or duplicate another chat's work.
- Do not add tests, coverage targets, test matrices, testing frameworks or additional test environments during alpha unless the user explicitly requests them. Comprehensive test coverage is not an alpha delivery requirement. Focus on basic usability and the smallest verification necessary for the approved delivery. Do not proactively run local tests, builds, linters, type checks or browser QA; run them only when the user explicitly requests local verification. Repository-required CI gates may still run as part of an explicitly requested push, merge or release workflow.
- Preserve existing required CI gates. For an existing failure, distinguish a product defect from a test-fixture defect and make the smallest relevant correction. Do not bypass gates, fabricate results or remove checks merely to report success. Passing a configuration check or a partial test is not proof of a usable deployment.
- Before introducing any new project dependency, obtain explicit user approval. Explain its purpose and necessity, whether existing dependencies can satisfy the need, and its maintenance, security and size costs. This includes runtime, development and testing dependencies; do not add first and ask afterward.
- Keep implementation, verification, CI, commit/push, merge, release and production deployment distinct. Respect the authorization for each stage, protect existing data and other chats' uncommitted work, and never infer production permission from a development or documentation request.
- Report meaningful progress, failures and decisions needed, rather than repeated unchanged status. When idle, inspect existing issues and propose a small complete next step; do not start unapproved work merely to stay busy.

## GitHub releases and Actions storage

- Use Release Please v5, pinned to a reviewed full commit SHA. Create or update
  version PRs from the operator workstation with `python3 scripts/prepare-version-pr.py`
  and the existing maintainer Git login. Do not create version PRs with the CI
  `GITHUB_TOKEN`: GitHub holds their PR workflows for approval. Do not add an App,
  PAT, CI credential or dependency for this operation. Actual CI and release
  publication continue using the built-in `GITHUB_TOKEN` and minimal permissions;
  never weaken branch protection to enable releases.
- Release through the generated version PR and the repository's Release Please
  config/manifest. Use Conventional Commits, including the final squash title;
  do not hide a releasable fix under a `ci:` or `chore:` title. Do not manually
  bump versions, move tags, or add a second tag-triggered release path.
- Required checks must represent real checks on the exact version PR head SHA.
  Maintainer-created version PRs must trigger the existing `pull_request` checks.
  A `workflow_dispatch` run cannot substitute for required PR workflow checks.
  Do not automate approval, fabricate checks or bypass protection; metadata
  validation is not a substitute for CI or CodeQL.
- Publish only from an immutable, checked commit on protected `main`. Use the
  Release Please output SHA/tag throughout checkout, build, provenance and
  publication; fail closed on identity/version mismatches or failed checks.
  Do not assume a tag created with `GITHUB_TOKEN` triggers another workflow.
- Keep releases as drafts until all required builds, integrity/provenance checks
  and uploads succeed. Retain only the distribution files and metadata required
  by users or verified consumers. Retry failed jobs or an explicitly documented
  recovery flow; never overwrite an already published release or move its tag.
- CI and manually dispatched maintenance workflows do not retain downloadable
  Actions artifacts: no binaries, UI bundles, browser evidence, source patches,
  workspace copies or build records. Do not add upload/download-artifact steps
  or retention-based exceptions for these files. Only explicitly requested test
  coverage reports may be uploaded, with narrowly scoped contents and short,
  documented retention. Keep the actual tests and required CI gates.
- Set `DOCKER_BUILD_RECORD_UPLOAD=false` for Docker build actions. Keep bounded
  dependency/build caches for CI speed; caches are not release artifacts.
  Stage necessary cross-job release files directly in the draft Release rather
  than keeping duplicate Actions artifacts.
- Artifact cleanup must enumerate exact targets, skip active runs and artifacts
  required to recover failed releases, and preserve published Release assets and
  caches unless separately authorized. Never include credentials, production
  data, private host details or full subscription URLs in files or logs.
- Distinguish workflow edits, successful CI, successful publication and production
  deployment in completion reports. A green preparation job with skipped publish
  jobs is not proof of a release. Documentation edits do not authorize a push,
  merge, release, signing operation or production deployment.

- Read `RELEASING.md` before changing release workflows. Keep the UI package,
  lockfile and release manifest versions aligned. A Glivela source release does
  not publish its UI into the signed application catalog or upgrade an installed
  runtime; those are separate, explicitly authorized operations.

## Petauron 团队：Issue 跟踪与完成标准（MVP）

- 开发每项已获授权的功能或缺陷修复前，先查找并关联对应仓库的现有 issue；没有合适的 issue 时先创建，简要写明用户目标、最小范围和完成标准。不要重复创建，也不要把创建 issue 当作扩大实现或部署授权。
- 一项完整需求或缺陷使用一个主 issue 持续跟踪；开发、修复、CI、合并、发布、部署和验收复用它，不为每个操作、重试或版本单独建 issue。跨仓库工作优先在主 issue 关联各仓库 PR，只有可独立交付的问题才拆分 issue。
- PR 必须关联主 issue，并将 PR 链接、关键 CI 结果、发布版本及链接、适用的部署和验收结果回填到同一 issue。记录简洁、真实且可核验；未执行、失败、阻塞和尚未完成的步骤明确标注，不记录凭据、完整订阅链接或私有环境敏感信息。
- 只有约定范围实际完成且有相应验收证据后才关闭 issue。CI 通过、PR 合并或源码发布不自动代表部署及用户功能验收完成；范围包含部署或实测时，完成前保持 issue 开放，PR 使用关联引用而非会导致提前关闭的自动关闭关键词。
- 按 MVP 保持最小记录，不增加形式化审批、重复报告或额外测试要求。仅涉及代码或文档的任务，按其已约定完成标准关闭，不强加无关的发布或生产验收；所有操作仍遵循用户授权和现有 CI、安全规范。

## Public source and upstream references

- Public examples and fixtures use synthetic node labels and documentation
  addresses. Keep fleet inventory, private operational records, credentials and
  complete subscription URLs outside the source repository.
- Do not hardcode an operator's vendor aliases or host-specific table names into
  product behavior. Preserve explicit operator-provided display names and strict
  authorization/ownership boundaries.
- Public references to upstream issues/PRs must use `redirect.github.com`, including
  Markdown link targets. Do not also include the original `github.com` issue/PR URL
  or `OWNER/REPO#123` shorthand. Internal issue/PR tracking remains required.
- Do not push branches, tags or Git objects from the private historical repository
  into this clean baseline. Bring approved changes across as reviewed differences.
