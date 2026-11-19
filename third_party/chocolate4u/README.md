# Chocolate4U Iranian IP dataset provenance (development QA)

- Project: https://github.com/Chocolate4U/Iran-sing-box-rules
- Dataset branch: `rule-set`
- Pinned source commit: `085deb78a67cc3452ee0ad071ed476024d34d92f`
- Exact source: `geoip-ir.srs` at that commit
- Original binary SHA-256: `b17601400d00fc26ecdda16b13469460878d929f3c35311e666f9149015f8ba4`
- Transformed with **official sing-box 1.14.3** `rule-set decompile`, no added or deleted source ranges
- Exact transformed source: `internal/sc/data/iran-chocolate4u-2026-11.json`
- Transformed SHA-256: `c80922639511fc817957f1ecb018b0f13855decc59c5fbe492fac5bdb6638616`
- Repository license: **GNU GPL v3**. The retained exact project `LICENSE` comes from main commit `33fa2596e08bd20c47ecf276d21883cec36b1dfc`, SHA-256 `3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986`. Derived upstream datasets may have their own source/attribution conditions.

This is **country categorization, not proof of geographic host location or destination reachability**. The dataset includes provider-operated addresses hosted outside Iran; unlike an Iran-first consumer client, a hosting-server Direct bypass cannot safely assume every Chocolate4U `geoip-ir` member is physically in Iran. Server Connect's default native `bypass_iran` policy uses the CIDR-accurate **intersection** of this dataset with separately attributed, versioned DB-IP Lite, after independently validating both embedded sources. An operator may choose `--iran-coverage dbip` to retain the prior DB-IP-only estimated coverage. Neither choice can certify access to any individual endpoint.

No online downloads or silent refreshes occur at activation. Source reviews, upstream version/digest and appropriate attribution/license decisions belong to **each new authenticated product build**. The product license, third-party redistribution obligations, real official/mirror publisher identity and public release remain unapproved and outside this QA source's authority. Never publish a bundle on the strength of checksum validation alone.
