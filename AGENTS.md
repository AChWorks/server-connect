# Server Connect — contributor and Master instructions

- Start with README.md and **docs/PROJECT-SPEC.md**. The specification is the single durable product authority; do not invent behavior or use past chat to override it.
- Reconcile current main, relevant **open Issues**, PRs, CI, release assets and tested deployment evidence. A closed Issue or prior mock is not current acceptance.
- Apply the repository-local project, architecture, safety, offline distribution, and acceptance contracts. This public repository must remain understandable without access to private company resources. Never mutate another repository without its own explicit authorization.
- Current repository mutation scope is **AChWorks/server-connect** only. Existing STL, SSO, external tunnel tools, aaPanel and customer services remain separate resource owners; preserve them.
- First core is **official pinned sing-box**; do not build a replacement transport or a generic provider framework without measured need.
- Author repository documentation, Issues, contributor guidance, and technical comments in English. Optional future product localization is a separate user-facing feature.
- Favor minimal native Linux/service capabilities, clear CLI+JSON contracts and a small reversible host footprint. Keep settings, secrets and runtime state out of Git.
- Never install/alter a production server, public routing, SSH/firewall/DNS or customer sites without specific current authorization. Test on disposable isolated hosts; retain console/snapshot and exact cleanup evidence.
- Any route-affecting implementation requires independent Activation Guard, running Runtime Health Guard, owned-resource rollback, tested crash/reboot recovery and mandatory negative/field evidence defined in docs/ACCEPTANCE.md.
- Changes require focused tests, exact-candidate proof appropriate to risk, and high-assurance author-separated independent review for privileged/network code before integration and release.
- Persist lasting product decisions in docs/PROJECT-SPEC.md only when accepted behavior changes. Store technical operational contracts in their specific docs, active work/dependencies in Issues, results in PRs/CI, production truth in the actual runtime; no chat-based manager snapshots.
- Do not claim an offline installer, Linux compatibility, safe recovery, active VPN path, installed core or released build until the corresponding physical evidence exists.
