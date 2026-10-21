# Server Connect

**Offline-first, fail-safe Linux server connectivity manager (planned; not yet installable).**

Server Connect is a private AChWorks project for Linux hosting administrators. In ordinary conditions the host stays **Direct**. When desired, the operator can import a validated VPN/proxy profile, use only selected applications through a proxy, or activate guarded split/broader outbound routing without intentionally breaking domestic access, SSH, aaPanel or hosted sites.

**First upstream core:** sing-box. **Critical differentiator:** rollback both during activation and when an active VPN path later fails. Offline installation is a first-class requirement, not an afterthought.

فارسی: این پروژه برای مدیریت آسان و امن اتصال‌های بین‌المللی سرورهای Linux ایران طراحی شده است. در حال حاضر **هیچ نسخه نصب‌شدنی منتشر نشده** و فایل یا دستور نصب واقعی وجود ندارد.

## Product map / source of truth

| Need | Read |
| --- | --- |
| Accepted goals, behavior, constraints, non-goals | [Project specification](docs/PROJECT-SPEC.md) — canonical |
| Components, boundaries and third-party reuse | [Architecture](docs/ARCHITECTURE.md) |
| Activation confirmation, recovery and health guard | [Safety & recovery](docs/SAFETY-RECOVERY.md) |
| One-folder offline installation and package trust | [Offline distribution](docs/OFFLINE-DISTRIBUTION.md) |
| What must be physically tested before release | [Acceptance](docs/ACCEPTANCE.md) |
| Contributors / replacement Master rules | [AGENTS.md](AGENTS.md) |
| Current work and implementation results | [Repository Issues](https://github.com/AChWorks/server-connect/issues), PRs, CI and releases |

**No VPN endpoints, paid profiles, private keys, credentials, site/customer data or operator secrets belong in this repository.**

## Intended user journey (not implemented)

1. Download one verified, compatible complete offline release bundle on a trusted networked machine.
2. Copy it to a private folder on the target Linux server and execute its documented **local** installer once.
3. Start a simple terminal menu; import and validate a compatible sing-box/VLESS profile.
4. Choose Direct, Proxy Only, Selective Tunnel or Broad Tunnel; pick failure and probe policy.
5. A route-affecting mode is temporary until independently checked and confirmed; if later connectivity degrades, the guard restores the selected safe network policy.

Foreign reachability of customer websites is **optional and selected by the operator**, not a mandatory condition for using a VPN to download updates.

## Project limits

This project manages its own host-network changes, **not** a new VPN protocol, a mandatory cloud service, the aaPanel web stack or other AChWorks repositories. A client VPN does **not** automatically grant inbound public connectivity. Successful Windows configuration use does not prove that the same remote endpoint works from a specific Iran datacenter.

Only advertise OS/protocol/performance support after exact-version, offline-package and real host evidence. No production deployment is authorized by the creation of this repository.
