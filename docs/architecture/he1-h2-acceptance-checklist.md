# H2a 逐节点验收清单

- 状态：**执行索引**，2026-11-21 建立，尚无任何实现。
- 权威：`docs/adr/0128-package-and-bundle-contract.md` 是唯一规范来源。本文件
  只把 `docs/architecture/he1-h2-plan.md` §5.1–§5.3 的测试行映射到负责节点，
  不新增、不放宽、不重解释任何规则；发现规范缺口时改 ADR，不在本文件里另立一条。
- 为什么先有它：计划 §5 要求 H2a 的第一个实现 PR 之前建立逐节点清单，避免多个
  实现 PR 各自满足局部测试却遗漏跨章节约束。本文件是该要求的交付物。
- 用法：一个节点一个 PR；PR 只认领本文件里该节点的行。一行算完成的条件是
  **列出的测试真实存在并通过**，不是「代码写了相关函数」。测试名是计划里的
  `拟名`；改名必须同时改计划对应行和本文件，否则索引会漂移。

## 0. 这份清单不是

- 不是第二套语义权威，也不是完成度计数。没有状态列：完成与否由 PR 与绿色运行
  记录证明，不在这里维护第二个手写数字。
- 不证明 ISA 编码正确性。测试通过只说明本行的断言成立；独立编码证明仍是
  H4/H5 的义务（计划 §4.3）。
- 不表示 H2b/H2c 的工作可以提前宣称完成。V-P 未通过前，所有 lock/sealed/legacy
  都是开发产物。

## 1. 节点与交付边界

| 节点 | 结论 | 交付 | 退出条件 |
|---|---|---|---|
| N1a | V-A | manifest/spec/lock 封闭形状、词法、双冲突域、单一 `LoadedPackage`、能力推导、源/证据摘要、跨语言向量 | §2 全绿 |
| N2 | V-A | 严格排序、显式闭包、归属与身份唯一、form ⊆ 包 ⊆ bundle、九键 sealed、builder 投影、`CheckedBundle`/compat | §3 全绿 |
| N3 | V-A | 独立身份、`verify --package`、cases 与证据、差分指针、Level 0/1 投影、`D_form`、`package_conformance` 执行 | §4 全绿 |
| N4a | V-A | 写阶段原子性、`--check` 有界流式比较、legacy 等价门禁、孤儿枚举 | §5 全绿 |
| N1b | V-P | 三平台 PoC 行 + 硬化打开（含精确名字查找、目录项替换）+ 输出父目录 | §6.1 全绿 |
| N4b | V-P | 登记表格式与全历史审计，只用合成树与临时目录 | §6.2 全绿 |
| N5a | V-P | 变更路径门禁、合并新鲜度 `(B_checked, C_checked, mode)`、stale-CI 反例 | §6.3 全绿 |
| N5b | V-P | 首次发布：登记当时 HEAD 的全部 spec 闭包 | §6.4 全绿 |
| N6 | H2c | aarch64/rv64 包、三 ISA conformance、报告 | §7.2 全绿 |

V-A 节点（N1a/N2/N3/N4a）不等待任何外部平台事实；V-P 节点（N1b/N4b/N5a/N5b）
任一失败只停止发布结论，不回退作者层已证明的事实。

## 2. N1a — 词法、闭合形状与摘要

单次打开得到一份 `LoadedPackage`；摘要计算、legacy 行/目标比较、逐包 `read` 和
合并都消费同一份值。可信树读取只用普通打开，**不**声称已具备 V-P 的不跟随保证。

- `a_file_change_between_digest_and_merge_is_not_observed` — 摘要与合并必须消费同一份已加载字节；不允许摘要来自 A、合并来自 B；重放得同一 `definition_digest`。`H2-D9`、`ADR-0128` §9
- `a_package_path_cannot_escape_its_root` — `../`、绝对路径、任一中间段越界在打开前拒绝（`path-escape`）；不跟随与替换绑定部分见 §6.1。`H2-D3`
- `identifier_and_path_lexical_rules_are_platform_independent` — 大写、空段、尾点、Windows 设备名在三个平台都是格式拒绝（退出 1），不是某平台 I/O 失败。`ADR-0128` §1.3；证据：三平台
- `the_same_relative_path_in_two_packages_is_legal` — 包根相对冲突域与仓库根相对冲突域分离；两个包各自的 `forms/add.json` 合法。
- `a_cross_package_path_alias_is_rejected` — 两个包根折叠成同一仓库路径，或同一 `packages[].path` 列两次 → `path-lexical`。
- `a_package_path_keeps_the_full_package_id` — 目录段等于完整 `package_id`；`monasm.x86.crypto` 与 `vendor.x86.crypto` 可共存。
- `the_manifest_is_closed` — 未知键、缺必需键、重复键拒绝；可选键缺失合法。`INV-07`
- `an_empty_forms_list_is_refused` — `exports.forms: []` → `empty-package`，在 `read` 之前拒绝。
- `an_unknown_capability_is_refused` — 白名单外字符串 → `unsupported-capability`。
- `a_capability_must_be_declared_if_a_row_uses_it` — 声明 `[]` 而有带 `placements` 的槽位 → `capability-mismatch`。
- `a_declared_capability_must_be_used_by_a_row` — 声明 `integer-domain/v1` 但无 `operand_value` 槽位 → `capability-mismatch`。
- `a_duplicated_capability_is_rejected` — 重复能力 → `capability-lexical`，且不进入任何摘要。
- `a_reversed_extension_array_is_rejected` — 同一集合只有升序一种写法；清单侧在此，spec/lock/sealed 的同规则在 §3。`H2-D7`
- `a_non_empty_reserved_asset_is_refused` — 非空 `exports.types`/`profiles` → `unsupported-asset`。
- `a_non_empty_reserved_asset_is_refused_forever_under_0_1` — `monasm-package/0.1` 的含义由版本决定；升级构建器不得把同一份清单从拒绝变成接受。
- `a_case_evidence_must_be_listed_and_hashed` — 清单存在时，用例证据未列出或哈希不符 → `case-evidence-mismatch`。
- `an_evidence_hash_covers_raw_file_bytes` — 哈希对象是原始字节；CRLF/LF、缩进、尾随换行都算变更。
- `the_case_file_is_part_of_the_release_digest` — 改 `tests/cases.json` 并同步清单 → `evidence_digest`/`release_digest` 变，`definition_digest` 不变。
- `the_release_mode_requires_complete_evidence` — 缺 cases 条目、`NOTICE`、`sources`、`oracle.status` 或 skip 理由 → `evidence-incomplete`。
- `a_deep_json_document_is_refused_before_recursion` — 深度扫描先于 `json::parse`，不靠栈溢出兜底。
- `the_asset_budget_is_counted_while_reading` — 累计到上限即拒绝，不只信 `stat`，也不被读时增长的文件绕过。
- `the_legacy_source_path_components_are_strict` — `isa`/`version` 在拼路径之前按组件校验。
- `only_executable_inputs_enter_the_source_digest` — README/NOTICE 不入源摘要；form 行改动入。
- `evidence_changes_do_not_move_the_definition_digest` — 证据变化只动 `evidence_digest`/`release_digest`。
- `an_evidence_entry_must_stay_inside_the_package_and_match_its_hash` — `../` 或错误 sha256 → `evidence-mismatch`。
- `release_digest_tracks_the_release_not_the_builder` — 同 bundle 不同证据 → 不同 release 摘要；builder 版本变化不影响。
- `changing_the_legacy_source_changes_the_source_digest` — `0.1.0` 改成 `0.78.0` 改变源摘要；行未改时行相等测试随即失败。
- `the_artifact_filename_matches_its_bundle_id` — spec/lock/sealed/legacy 文件名必须等于 `bundle_id`，否则 `bundle-file-mismatch`。
- `a_legacy_package_target_must_match_its_source` — 行逐字节不变但 `execution_mode`/`address_width` 改动 → `legacy-target-mismatch`，在 `read` 前拒绝。
- `a_set_equal_target_migrates_a_differently_ordered_legacy_array` — `TargetEq` 按集合比较扩展；新包仍按升序写，legacy 原样保留。
- `the_digest_preimage_vector_matches` — Rust 与 Python 都得到 `1afee65c…`；把嵌套摘要写成原始 32 字节则不匹配。证据：跨语言向量
- `a_dependency_object_is_closed_and_keeps_its_vector` — `637edab0…`，依赖项自身 `sha256:231b9034…`；改键名/删键/加键/写 `latest` 都拒绝。证据：跨语言向量
- `the_bundle_and_release_vectors_match` — 两端都得到 `a9bc3395…`/`2416911a…`；改域分隔或漏键即不匹配。证据：跨语言向量
- `the_release_shaped_vector_matches` — `e9473871…`/`45a4004e…`；漏 `evidence_digest` 会退化成开发形状，因此提交的 lock 不能写成开发形状。证据：跨语言向量
- `resource_limits_are_enforced` — 文件数、大小、路径、依赖深度、闭包累计、资产数、嵌套深度的上限；具体预算行分属 §3/§4/§5，本行是总入口。
- `every_package_form_equals_the_pinned_legacy_row` — 逐 form canonical 相等，比较对象是钉住版本。`HE-AC-03`、`HE-AC-11`；H2a 只覆盖 x86
- `a_form_row_is_compared_against_its_pinned_version_not_the_newest_file` — 把钉住版本换成最新文件即判不等；构建器不自动改用最新。
- `editing_cases_json_changes_the_release_identity` — 改用例并更新清单 → 证据/发布身份变，机器码与 `definition_digest` 不变。
- `evidence_digest_tracks_case_evidence` — 改证据文件或清单 → `evidence_digest`/`release_digest` 变，`definition_digest` 不变。

## 3. N2 — 闭包与 sealed

严格排序、显式闭包、归属与身份唯一、form ⊆ 包 ⊆ bundle、合并前逐包 `read`，
以及由 sealed 自身重算两个摘要。

- `the_same_inputs_build_to_the_same_bundle_digest` — 两次构建、两个临时目录、不同创建顺序 → 同一 `bundle_digest` 与同一 sealed 字节。`HE-T05`
- `an_unsorted_spec_is_rejected` — spec 的 `packages` 逆序或非严格排序 → 确定性拒绝，不静默重排。`HE-T16`
- `package_discovery_order_does_not_change_the_bundle` — 目录创建顺序、读取顺序、内部集合迭代顺序都不影响字节。`HE-T16`
- `an_unselected_package_does_not_change_an_old_bundle` — 包根新增一个未列出的包（即使清单损坏）→ 旧 spec 的 lock/bundle 不变，构建器从未打开它。`HE-AC-05`
- `a_dependency_outside_the_spec_is_refused` — 依赖指向列表外 → 拒绝，不扫描目录补齐。`H2-D5`
- `the_spec_lists_every_package_in_the_closure` — 删掉一个被依赖的列表项 → 拒绝。`H2-D5`
- `a_dependency_must_match_its_exact_digest` — 改依赖内容保留版本 → 摘要不匹配，退出 1。`HE-T08`
- `a_dependency_cycle_is_refused` — A→B→A 确定性拒绝，不递归溢出。`HE-T08`
- `the_same_dependency_reached_twice_is_loaded_once` — 菱形闭包中共享包只列一次，两条边都校验，归属表无重复。`HE-AC-04`
- `two_packages_exporting_the_same_form_conflict` — 同一 `form_id` 内容相同也失败。`HE-T07`、`HE-AC-09`
- `two_versions_of_one_package_id_conflict` — 同一 `package_id` 两个版本、导出不相交 → `version-conflict`。
- `a_file_form_id_must_match_its_export` — 交换两个 form 文件 → 归属不匹配，拒绝。
- `two_packages_with_equal_target_identity_and_distinct_profile_labels_can_compose` — 组合看六键身份，不看 `target_profile` 标签；只改 B 的一个身份字段即拒绝。
- `a_standalone_identity_cannot_be_written_into_a_spec` — `monasm.standalone.`/`standalone+` 前缀 → `reserved-identity`。
- `a_frozen_legacy_definition_name_cannot_be_reused` — 冻结的 `definitions/*/*.json` 名字不可复用、也不可登记；保留集合只读、不进摘要。
- `a_form_family_must_match_the_package_target` — aarch64 包导出 `x86:*` → `form-family-mismatch`，在 `read` 之前。
- `the_family_rule_is_equality_not_a_package_whitelist` — `loongarch` 通过包层检查，只被现有 `definition::read` 拒绝；错误来自 reader。
- `a_package_cover_is_a_subset_of_the_bundle_target` — `fmp-def/0.2` 合成包覆盖 ⊆ spec 选择；缺成员拒绝。
- `a_form_requirement_must_be_inside_its_own_package` — 逐 form `requires_extensions` 超出本包覆盖 → `form-extension-mismatch`，在包 ⊆ bundle 之前。
- `an_over_declared_extension_cover_is_legal_but_narrower` — 高报合法且不裁剪；spec 只选子集才失败。
- `fmp_def_0_1_keeps_the_transitional_exact_target` — 0.1 的覆盖与选择不等（即使子集）→ `h2-exact-target`。
- `a_profile_id_is_not_a_global_target_identity` — 同一 `profile_id`、不同 `enabled_extensions` 各自构建；H2 不加跨 spec 唯一性。
- `the_closure_budget_counts_case_and_evidence_bytes` — 三包各 24 MiB、累计 72 MiB 越 64 MiB → 越界那次读取处 `aggregate-limit`；共享包只计一次。
- `the_builder_identity_is_not_part_of_the_definition_digest` — 两个 builder 版本 → 同 definition/bundle 摘要，lock 的 builder 不同。`HE-T19`
- `the_generated_definition_is_read_by_fmp_model` — 坏 form 行由 `read` 拒绝，构建器包装该拒绝，不复制检查。`H2-D12`
- `the_compat_bridge_cannot_widen_back` — 无 `definition()`、无反向构造，doctest `compile_fail`；`fmp-validate`/`fmp-materialize` 依赖图不含 `fmp-definition`；`bundle_json()`+`read` 的绕过路径能编译但不能当 bundle 证据。
- `the_output_is_canonical_json` — 无空白、键排序、无尾随换行，与 Python canonical 一致。证据：跨语言
- `the_spec_lock_and_sealed_shapes_are_closed` — 三者未知键/重复键被拒；`builder.build` 缺省时省略键而不是写 `null`。
- `a_sealed_bundle_verifies_its_own_digest` — 只拿 sealed 字节重算两个摘要都等于记录值；改 `bundle_digest` → 自校验失败。
- `the_sealed_bundle_key_set_is_exactly_nine_keys` — 排序后恰好九键；加 `sources`/`path`/`builder`/`release_digest` 都是未知键。
- `the_form_owner_map_is_complete_and_inside_the_digest` — N 个 form 恰好 N 行；删、重、多、owner 不在 `packages` 中 → `bundle-owner-incomplete`；只改 owner 也改变 `bundle_digest`。
- `a_bundle_id_may_advance_to_a_new_definition` — 同一 `bundle_id` 可推进到新包版本；同时存活的两个 spec 共用仍 `bundle-id-conflict`。
- `two_specs_cannot_share_a_bundle_or_definition_identity` — 共用 `bundle_id` 或 `(namespace, version)` → 冲突；三项都合法后 `--all --check` 通过。
- `a_package_update_does_not_edit_an_old_spec` — 只新增版本目录，不动 spec/lock，旧 lock 字节不变。`HE-AC-05`
- `the_package_export_set_is_exact` — 导出集合等于清单声明集合，没有隐藏 form。`HE-AC-03`
- `a_cross_isa_form_is_rejected_before_read` — 声明 aarch64、导出 x86 form → 不进入合并文档。

## 4. N3 — 独立身份与 conformance

`monasm-standalone/0.1` 身份、`verify --package` 的静态契约、`package_conformance`
的执行判定，二者是两行独立结论。

- `an_unknown_case_format_is_refused` — `monasm-cases/0.2` 或其他值 → `case-format-unsupported`，在解析用例前。
- `a_package_without_legacy_source_is_verified_from_its_own_target` — 合成包按自述目标、`read` 和用例通过，不需要 spec。
- `the_standalone_identity_is_derived_from_the_package` — 复制包到不同目录、换 cwd、无 spec → 同一独立身份与同一独立摘要。
- `the_case_file_is_required_and_covers_every_form` — 缺文件 `missing-cases`；某 form 缺正例或缺 `scope:"form"` 负例 → `uncovered-form`。
- `a_case_must_bind_its_declared_form_to_the_plan` — case 声明 B、计划执行 A/空/多指令 → `case-form-mismatch`，不进入执行。
- `a_case_negative_must_target_the_declared_instruction` — 根级或 `/sections/...` 诊断 → `case-error-scope`；`mutates` 指 `expected_digest`、多改或没改 → `case-mutation-mismatch`。
- `a_form_negative_must_be_a_bind_rejection_on_the_mutated_operand` — form 负例只接受 `bind`；`E-BYTE-001`/`E-SIZE-001` 冒充不算覆盖。
- `a_read_stage_rejection_is_a_plan_negative` — 读取器拒绝的计划只能 `scope:"plan"`+`stage:"read"`；观察集是单条 `Diagnostic`。
- `a_declared_stage_must_be_the_first_rejecting_stage` — 声明阶段必须恰是第一个拒绝阶段，否则 `case-error-scope`；`verify --package` 不替代此判定。
- `a_modifier_value_change_is_a_single_form_mutation` — 0.2 fixture 改 `modifiers/0/value` 是单次变异；诊断落在 `…/modifiers`（祖先）。
- `a_development_package_verifies_without_an_evidence_manifest` — 无清单开发模式通过且不产生 `evidence_digest`；`--release` → `evidence-incomplete`。
- `release_evidence_is_a_separate_gate` — 有依赖无闭包：`--release-evidence` 退出 0，`--release` 退出 1（`dependency-unverified`）。
- `case_and_evidence_inputs_have_their_own_budget` — `tests/cases.json` 16 MiB、证据清单/spec/lock 1 MiB、forms 1024、assets 2048、文件数 4096；未选中包也受限。
- `a_boundary_positive_lies_in_the_final_legal_domain` — 正例取 `D_form` 成员（三个真实 form 的端点已给）；原始端点被排除或未对齐就不是正例。
- `a_degenerate_legal_domain_needs_no_invented_positive` — 基数 1 只要一个值、基数 2 只要两个；基数 0 且无非数值路径 → `empty-form-domain`。
- `an_empty_numeric_domain_with_a_fixup_path_is_not_rejected` — `operand_value` 空数值域加 fixup/符号路径仍合法；构建器不得比验证器多拒绝。
- `level_zero_and_level_one_projections_are_exact` — Level 0 多 `symbols` → `case-expect-shape`；Level 1 只在 `include_symbol_table` 为真时出现 `symbols`。
- `a_dependent_package_is_structure_verified_but_closure_unverified` — 无闭包时打印 `dependency_closure: unverified`；`--release --closure <lock>` 匹配后通过。
- `a_handwritten_closure_digest_is_not_trusted` — lock 写不存在的 path 或错摘要 → `dependency-mismatch`，不报告 `verified`。
- `the_transitive_closure_is_fully_rechecked` — A→B→C 缺项、错摘要、版本不符、成环全部 `dependency-mismatch`。
- `a_representative_form_proves_its_bounded_operand_domain` — 按 `D_form` 基数取正例；证据只要求诊断实际携带的键（`min`/`max`/`value`、`target_type`/`value`/`field_bits`、`excluded`）；pass 条件仍是 `(code, path)` 集合。`ADR-0128` §9.1
- `a_wide_register_slot_keeps_the_h1_encoding_domain` — 127/192 位槽位用 `0` 与 `u64::MAX` 走通，不要求 `2^127`；把作者层域硬编码成 64 位即失败。
- `a_static_stage_claim_is_not_a_dynamic_rejection` — 静态检查可通过，执行后必须判 `case-error-scope`；报告分开记录两行状态。
- `verify_package_reads_the_definition_not_the_plan` — 定义非法 → 退出 1；计划非法但定义合法 → 仍退出 0，只有 conformance 执行后按 stage 判定。
- `the_x86_package_reproduces_legacy_machine_output` — X86-P1 的 §4.2.1 精确投影相等。`HE-T18`
- `the_only_difference_is_the_definition_identity` — 除指纹/定义身份外无字段差异；错摘要被 `bind` 拒绝。`HE-T18`
- `a_package_without_a_spec_is_still_checked` — 未进任何 `bundles/specs/*.json` 的包仍被 `verify --package` 确定性地检查。
- `a_synthetic_package_without_legacy_source_is_accepted` — 沿用现有 family、form 不在 legacy 目录也通过，证明协议不依赖历史定义。
- `a_wrong_opcode_in_a_structurally_valid_row_fails_the_package_gate` — `read` 仍通过，正例字节比较失败。`HE-T18`
- `the_conformance_harness_discovers_packages_without_a_central_list` — 新增包不动任何中心文件，harness 自动发现并执行其 cases。`HE-T14`
- `a_package_pr_runs_only_the_affected_conformance_set` — 受影响集 = 变更包 + 依赖可达；改核心 crate/路径层/harness 则全量；过滤不改变任何断言或摘要。
- `a_copied_package_yields_the_same_standalone_check` — 不同目录、不同 cwd 的副本 → 同身份、同诊断、同独立摘要。
- `a_case_form_claim_is_bound_to_the_executed_plan` — 改 case 的 `form_id` 而计划仍编码 A → 失败，B 不算已覆盖。
- `an_unrelated_plan_error_does_not_cover_a_form` — 错 `expected_digest` 的 plan 负例不计 form 覆盖；标成 form 则 `case-mutation-mismatch`。
- `a_form_negative_mutates_exactly_one_operand_field` — 只改 src2 通过；再改 `offset`/`expected_size` → `case-mutation-mismatch`。
- `the_case_diff_pointer_is_algorithm_independent` — 差分定义在最终值上；固定向量与两个独立实现结果相同。
- `a_form_negative_matches_the_complete_diagnostic_set` — 少一条或多一条都 `case-diagnostics-mismatch`。
- `a_package_change_does_not_touch_legacy_roots` — `definitions/`、`fixtures/`、`payload_root` 不变（H1 已证，此处复跑）。`HE-AC-10`

## 5. N4a — 写入与历史等价门禁

- `a_committed_sealed_bundle_over_its_budget_is_rejected` — sealed 超 80 MiB、lock 超 1 MiB → 有界比较在预算处停止并报 `resource-limit`，不 `read_to_end`，不改写文件。
- `an_output_parent_that_is_a_symlink_is_refused` — `--root` 下输出目录任一段是链接/reparse point → 写阶段在创建临时文件前 `path-escape`；不跟随实现属 §6.1。
- `the_legacy_snapshot_is_readable_by_load_dir` — 快照能被 `Registry::load_dir` 读；sealed bundle 放进定义目录被拒绝。
- `a_build_never_writes_a_snapshot_it_cannot_read` — 合并定义超过 16 MiB → 构建退出 0 但不写快照（并删除旧副本）；手工放入同尺寸快照 → `resource-limit`。
- `a_builder_field_change_is_not_a_provenance_proof` — 手改 lock 的 `builder` 仍通过、摘要不变；改 `definition_digest` 失败。该测试**不**证明构建来源。
- `failed_build_leaves_no_published_partial_artifact` — 写阶段 I/O 失败 → 退出 2，registry 未改，未报告成功，不留部分产物。
- `a_failed_legacy_write_leaves_no_stale_snapshot` — 第三个输出失败 → 退出 2；lock 与 sealed 都是新字节且互相一致，旧快照已删，`--check` 仍通过。
- `a_passing_check_does_not_prove_the_last_build_succeeded` — `--check` 只证明当前配对；从 git 检出而非本地构建写出的目录也通过。
- `a_single_bundle_build_does_not_prove_the_whole_tree` — 单 spec build 绿，`--all --check` 仍在另一个 spec 上失败。
- `a_modified_committed_legacy_snapshot_fails_the_bridge_gate` — 只改快照一个 opcode → `legacy-snapshot-mismatch`；删掉该文件通过（缺失合法）。
- `an_orphan_sealed_artifact_fails_artifact_closed` — 孤儿 sealed → `orphan-bundle-artifact`；`A(T)` 不能替代 `C(T)`。
- `a_retired_bundle_artifact_must_leave_the_tree` — 删最后一个 spec 必须同 PR 删 lock/sealed/legacy；包快照与登记项保留。

## 6. H2b / V-P 节点（列全，便于核对，不属 H2a 退出条件）

### 6.1 N1b — 三平台 PoC 与硬化打开

- `a_package_path_cannot_escape_its_root`（不跟随部分）— 任一段链接/reparse point、检查后替换目标 → 拒绝；不能只靠 `canonicalize()`。
- `a_case_different_on_disk_name_is_rejected` — 声明 `forms/add.json`、磁盘是 `Add.json` 或 `Forms/` → 三平台都是 `path-lexical`（退出 1），不是缺文件也不是成功打开；精确名字查找在已打开父句柄上完成。
- `the_no_follow_open_is_proved_on_three_platforms` — 中间目录链接、末段链接、Windows reparse point、检查后替换；目录项替换只能打开刚匹配的对象或 `path-escape`；FIFO 不阻塞。一个平台通过不算通过。
- `the_n1_poc_records_platform_toolchain_and_fault_injection` — 三平台各一行记录 OS、工具链与路径层 crate 版本（含 lockfile 项）、API/系统调用、注入方法与实际结果。已有初版记录在 `research/he1/n1b-poc/RESULTS.md`，是否逐项满足本行要求在开立 N1b 时核对。
- `a_fifo_leaf_never_blocks_or_passes` — POSIX 把资产换成 FIFO → 立即 `not-a-regular-file`，类型判定来自已打开句柄而非 `stat`。

### 6.2 N4b — 登记表格式与全历史审计

- `the_published_version_directory_is_immutable` — base 已登记目录内任何文件（含 `package.json`/`NOTICE`/`README`/`evidence/`/`tests/`）不可改；新版本用同级新目录。
- `a_first_publication_may_be_created_and_registered_in_one_pr` — 首次发布可同 PR 创建并登记；条目与最终 path/version/摘要不符或未被 head spec 选中 → `published-registry-invalid`。
- `first_publication_bootstraps_without_registry_cycle` — `build` 不要求登记行、从不写 registry；先追加再跑两项 `--check`，没有「先 check 后写行」的顺序。
- `a_successful_build_does_not_complete_the_registry` — 树里已有表时 `build` 退出 0，`--all --check` 仍 `published-registry-incomplete`。
- `a_base_published_version_cannot_be_edited_with_a_registry_change` — 包改动是 `published-package-modified`，登记改动是 `published-registry-modified`，两条独立。
- `a_retired_published_version_is_still_immutable` — 删除最后一个 spec 后改旧目录仍是 `published-package-modified`。
- `a_retired_definition_is_not_rebuilt_from_the_current_tree` — 审计重算包与快照、检查身份记录格式，但不重建已删除的闭包；报告不得写「已重算退役定义」。
- `a_retired_identity_digest_cannot_be_rewritten` — 改退役 `identities` 行由跨提交的 `PreservesPublished` 发现，不由当前树重算发现。
- `a_development_tree_without_a_registry_is_not_publication_ready` — 无表的树 `R(T)` 真而 `H(T)` 假，故 `Q`/`P` 假；`--published --check` 必须非零退出。
- `a_tampered_retired_version_fails_the_publication_predicate` — base 上已坏的退役快照由审计发现（`snapshot-mismatch`），不靠 `PreservesPublished`。
- `the_published_registry_is_append_only` — 删/改/重排/替换 base 条目 → `published-registry-modified`；head-only 条目在无 spec 选中时可撤销。
- `a_base_registry_deletion_fails_preserves_published` — 删表或删行都失败；`R(T)` 只从 `T` 读取，不用基线补洞；只改注释也失败。
- `a_published_identity_is_globally_unique` — 同一 `(package_id, version)` 换 path 或摘要 → `published-registry-invalid`；同一 path+摘要被两个 spec 引用 → 通过。
- `a_retired_definition_identity_cannot_be_reused_with_new_bytes` — 退役名换字节 → `definition-identity-conflict`；同摘要重新发布不新增第二行。
- `the_publication_audit_reads_retired_entries` — `--all` 不读旧包，`--published` 仍检查旧条目；未选中包不影响 `--all`。
- `the_publication_audit_covers_every_file_in_a_published_directory` — 任一文件（含 README/NOTICE/cases/evidence）变化都由重算的 `snapshot_digest` 发现。
- `a_published_snapshot_rejects_unlisted_nonregular_entries` — 未引用的符号链接、reparse point、FIFO、socket → `not-a-regular-file`，不跳过。
- `an_unreferenced_case_fold_collision_in_a_published_directory_is_rejected` — 未引用的 `notes/Manual.md` 与 `notes/manual.md` 并存 → `path-lexical`，理由固定为折叠。
- `a_published_version_cannot_change_evidence_in_place` — 已发布版本改 `tests/cases.json` 并同步清单仍是 `published-package-modified`。

### 6.3 N5a — 受保护合并与变更路径门禁

- `a_deleted_package_path_is_not_skipped` — 删除/重命名在 base 树解析；已发布目录删除是 `published-package-modified`；无法映射是 `unmapped-package-path`。
- `a_nested_package_manifest_cannot_mask_a_published_ancestor` — 先按 base registry 判定包含，head 侧更深的 `package.json` 不能重新归类。
- `a_concurrent_publish_freezes_the_old_commit_side` — 以目标分支尖端 `B` 为权威，不用 merge-base；用 merge-base 会错误放行。
- `a_stale_publication_verdict_cannot_authorize_a_merge` — 落地提交上重算 `B_landed`/`Tree(M)`，与记录不符即拒绝复用旧绿色结果。
- `a_publication_verdict_is_not_a_tree_predicate` — 同一棵树两种到达方式：只有经记录的合并操作才使 `P` 为真；报告分别列出六个合取项。
- `candidate_readiness_binds_gate_evidence` — 改 `e.base`、`e.tree`、门禁修订来源、授权状态任一项 → `Q` 假，`P` 不成立。
- `a_pr_cannot_weaken_the_gate_that_judges_it` — head 侧改过门禁不能为同一 PR 授权；必须先经受保护控制面或独立审批合入。在临时仓库或等价沙箱执行。

### 6.4 N5b — 首次发布

- `the_first_publication_registers_every_existing_development_bundle` — 首次候选为当时 HEAD 的全部 `bundles/specs/*.json` 闭包写 `published` 与 `identities`；只登记 x86 → `published-registry-incomplete`。
- `the_first_publication_lands_through_the_verified_channel` — N4b/N5a 的候选树没有真实 registry；只有 N5b 经 N5a 的通道写真实表，落地记录满足三元组。

### 6.5 V-P 规模测量（H2b 报告）

- `the_published_registry_cost_is_measured_at_one_thousand_versions` — 普通包变更、bundle 发布、全量历史审计各跑三次，记录耗时/峰值内存/读取字节/机器与工具链，并给**数值阈值**；只给曲线不给阈值即不合格。不出现在 H2a 退出门槛。

## 7. 其他阶段的行（列全，便于核对）

### 7.1 H3 验收（出现在 §5.1 但不由 H2 交付）

- `lifting_the_transition_needs_a_versioned_build_rule` — 0.1 的 `h2-exact-target` 永久保留；只有新的版本化构建规则能构建不相等的选择。
- `the_legacy_entry_does_not_claim_bundle_coverage` — 旧 `bind` 仍公开时，不得声称所有执行都经过 bundle 归属检查。
- `a_target_subset_requires_per_form_ownership` — 目标子集需要逐 form 归属证明；无证明默认拒绝，不按空集放行。
- `a_partial_form_requirement_cannot_override_owner_cover` — 未被证明完整的逐 form 键不能替代包覆盖；缺 `form_owners` 行仍拒绝。

### 7.2 H2c 覆盖（N6）

- `the_aarch64_package_reproduces_legacy_machine_output` — A64-P1、A64-P2 的 §4.2.1 精确投影相等。
- `the_rv64_package_reproduces_legacy_machine_output` — RV-P1、RV-P2 的 §4.2.1 精确投影相等。
- `packages_build_independently` — x86 与 rv64 各自构建，不读对方目录。`HE-AC-08`
- `the_three_isa_harness_has_no_isa_branch` — harness 只读清单/用例数据，源码审查加三种包覆盖。`HE-T14`

## 8. §5.3 门禁命令

H2 每个提交至少通过：

1. `cargo fmt --all -- --check`
2. `cargo test --workspace`（含 `fmp-definition` 测试与 `package_conformance`）
3. `python tools/check_ids.py`
4. `python tools/check_definition.py`
5. `python tools/he1_baseline.py --check research/he1/compatibility-results.json`
6. `tools/oracle/rerun.py`（`122/128`，6 跳过，0 失败）
7. `git diff --check`

H2a 新增、可放进现有 `workspace` job：

8. `cargo run -p fmp-definition -- verify --all --check` — 证明 `C(T)`（有登记表时还要 `R(T)`）；无登记表时把选中路径报告为开发产物，**不**报 `published-registry-incomplete`。
9. `cargo run -p fmp-definition -- verify --published --check` — H2b/V-P；证明 `H(T)`，只审计登记表全部条目，不选择包。
10. `cargo test -p fmp-definition --test package_conformance`（全量）与 `-- --affected <changed-path-list>`（普通包 PR）— 同一批断言，过滤只决定执行哪些包目录。

两项 `--check` 与 conformance 都是退出门槛，不是可选命令；取消任一项即门禁失败。

## 9. 非主张

- 行归属（哪一行算哪个节点）是执行索引的决定，不是规范决定；有争议时以 `ADR-0128` 的措辞为准，并单独提交修订。
- 本文件不声称任何行已经完成：H2 尚无实现，`packages/`、`bundles/`、`fmp-definition` 都还不存在。
- 「证据可追溯」不等于「编码正确」：作者可以同时提交错误定义、由该错误产生的期望字节和匹配的证据摘要，H2 的检查仍会通过。
