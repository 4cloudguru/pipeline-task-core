# Changelog

## [0.7.0](https://github.com/4cloudguru/pipeline-task-core/compare/v0.6.3...v0.7.0) (2026-08-24)


### Features

* add pem-normalizer ([#56](https://github.com/4cloudguru/pipeline-task-core/issues/56)) ([f4f496b](https://github.com/4cloudguru/pipeline-task-core/commit/f4f496bbba1f86ed18c3dca3959b367a7a58336c))

## [0.6.3](https://github.com/4cloudguru/pipeline-task-core/compare/v0.6.2...v0.6.3) (2026-08-23)


### Documentation

* add pem-normalizer to the module inventory ([#54](https://github.com/4cloudguru/pipeline-task-core/issues/54)) ([03c9dbe](https://github.com/4cloudguru/pipeline-task-core/commit/03c9dbe3992eb84bb1be5c008fe87ee9f5b28890))

## [0.6.2](https://github.com/4cloudguru/pipeline-task-core/compare/v0.6.1...v0.6.2) (2026-08-20)


### Documentation

* **security:** record the shared-workflow trust relationship, and fix what it invalidated ([#52](https://github.com/4cloudguru/pipeline-task-core/issues/52)) ([3e6b860](https://github.com/4cloudguru/pipeline-task-core/commit/3e6b860b12b7f8bb6453850e2bbff9907f2a9ca7))

## [0.6.1](https://github.com/4cloudguru/pipeline-task-core/compare/v0.6.0...v0.6.1) (2026-08-20)


### Bug Fixes

* **ci:** refuse to run signature-replay when Dependabot edited the workflow ([#44](https://github.com/4cloudguru/pipeline-task-core/issues/44)) ([89dd0e0](https://github.com/4cloudguru/pipeline-task-core/commit/89dd0e087be98f5849ec3fb55cab843a2367b170))

## [0.6.0](https://github.com/4cloudguru/pipeline-task-core/compare/v0.5.1...v0.6.0) (2026-08-16)


### Features

* share the credential-bearing raw-https transport ([#39](https://github.com/4cloudguru/pipeline-task-core/issues/39)) ([116ef09](https://github.com/4cloudguru/pipeline-task-core/commit/116ef093e79cc38cfa9e4c1bd9ca47c421b79c7f))

## [0.5.1](https://github.com/4cloudguru/pipeline-task-core/compare/v0.5.0...v0.5.1) (2026-08-14)


### Documentation

* point the advisory link at the repo's current owner ([#36](https://github.com/4cloudguru/pipeline-task-core/issues/36)) ([26f297b](https://github.com/4cloudguru/pipeline-task-core/commit/26f297b6dfc76c4330a22938cc1bc6f6fe4e8f9a))

## [0.5.0](https://github.com/4cloudguru/pipeline-task-core/compare/v0.4.0...v0.5.0) (2026-08-14)


### Features

* **proxy:** resolve HTTPS_PROXY/NO_PROXY for a given destination ([#34](https://github.com/4cloudguru/pipeline-task-core/issues/34)) ([63c208a](https://github.com/4cloudguru/pipeline-task-core/commit/63c208aa30619d7d007c6a7c7afdbb7af6f65939))


### Bug Fixes

* **http:** route remote text in messages through truncateForLog ([#33](https://github.com/4cloudguru/pipeline-task-core/issues/33)) ([23d3a0f](https://github.com/4cloudguru/pipeline-task-core/commit/23d3a0f928367a4380601b7604f4d9c538eead9f))

## [0.4.0](https://github.com/4cloudguru/pipeline-task-core/compare/v0.3.1...v0.4.0) (2026-08-13)


### Features

* **http:** add fetchStatusText so status-plus-body reads honour the byte cap ([#26](https://github.com/4cloudguru/pipeline-task-core/issues/26)) ([daf89e9](https://github.com/4cloudguru/pipeline-task-core/commit/daf89e909bc056a709bb57663004b8029f55a010))

## [0.3.1](https://github.com/4cloudguru/pipeline-task-core/compare/v0.3.0...v0.3.1) (2026-08-13)


### Bug Fixes

* **packaging:** make the ./gpg subpath types resolvable for CJS consumers ([#23](https://github.com/4cloudguru/pipeline-task-core/issues/23)) ([4a76caa](https://github.com/4cloudguru/pipeline-task-core/commit/4a76caaf7062bdbd9de98a26d09d367184719242))

## [0.3.0](https://github.com/4cloudguru/pipeline-task-core/compare/v0.2.0...v0.3.0) (2026-08-13)


### Features

* **gpg:** report why a detached signature did not verify ([#21](https://github.com/4cloudguru/pipeline-task-core/issues/21)) ([3a03c2c](https://github.com/4cloudguru/pipeline-task-core/commit/3a03c2c90758273214718f339a6404c412c30878))

## [0.2.0](https://github.com/4cloudguru/pipeline-task-core/compare/v0.1.2...v0.2.0) (2026-08-12)


### Features

* add proxy credential resolution ([#17](https://github.com/4cloudguru/pipeline-task-core/issues/17)) ([463d10f](https://github.com/4cloudguru/pipeline-task-core/commit/463d10f7faa27d1aa09d3f0555f12ae9c8cf9036))
* add the bounded-retry primitive ([#11](https://github.com/4cloudguru/pipeline-task-core/issues/11)) ([69b24d8](https://github.com/4cloudguru/pipeline-task-core/commit/69b24d8045acbaed4e0c60bf83666d70390fd8ce))
* add the egress authorization primitive ([#13](https://github.com/4cloudguru/pipeline-task-core/issues/13)) ([1dccbda](https://github.com/4cloudguru/pipeline-task-core/commit/1dccbda915135b0f4c19269f5bc0c9a42f53e1ff))
* add the HTTPS fetch and download primitives ([#14](https://github.com/4cloudguru/pipeline-task-core/issues/14)) ([bdfffbd](https://github.com/4cloudguru/pipeline-task-core/commit/bdfffbd0b1c20a92185a1657bbec4442bd79fffa))
* add the URL redaction and path-segment validators ([#15](https://github.com/4cloudguru/pipeline-task-core/issues/15)) ([702f500](https://github.com/4cloudguru/pipeline-task-core/commit/702f5003b1aa441cef87ab85dd62babfd54c3694))
* add the verification-failure marker and artifact discard ([#18](https://github.com/4cloudguru/pipeline-task-core/issues/18)) ([c99c322](https://github.com/4cloudguru/pipeline-task-core/commit/c99c322cb613f7bb2f72aed8fe252296d120cb22))
* implement detached-signature verification on the ./gpg subpath ([#19](https://github.com/4cloudguru/pipeline-task-core/issues/19)) ([190535c](https://github.com/4cloudguru/pipeline-task-core/commit/190535c2b569751bb644ba220c23a954b06777c6))

## [0.1.2](https://github.com/4cloudguru/pipeline-task-core/compare/v0.1.1...v0.1.2) (2026-08-12)


### Bug Fixes

* clear the four scanner findings ([#9](https://github.com/4cloudguru/pipeline-task-core/issues/9)) ([6bfe9ce](https://github.com/4cloudguru/pipeline-task-core/commit/6bfe9ceccba2b8c535591a4a22845471accce6c6))

## [0.1.1](https://github.com/4cloudguru/pipeline-task-core/compare/v0.1.0...v0.1.1) (2026-08-12)


### Bug Fixes

* **ci:** tarball check must ignore directories, not just files ([c7191fc](https://github.com/4cloudguru/pipeline-task-core/commit/c7191fc0c0ffbecf7cb9bed91a9c00e2e6bd9c25))

## 0.1.0 (2026-08-11)


### ⚠ BREAKING CHANGES

* publish as @4cloudguru/pipeline-task-core on public npmjs

### Dependencies

* bump actions/attest-build-provenance from 4.1.1 to 4.2.2 ([#5](https://github.com/4cloudguru/pipeline-task-core/issues/5)) ([0823281](https://github.com/4cloudguru/pipeline-task-core/commit/08232814f744f59e00ca5ddde4e18b4c2c596b9e))
* bump step-security/harden-runner from 2.20.0 to 2.20.1 ([#2](https://github.com/4cloudguru/pipeline-task-core/issues/2)) ([e58893a](https://github.com/4cloudguru/pipeline-task-core/commit/e58893a8cf1f81d5b15dbf2e0c398005579616f0))
* bump step-security/harden-runner from 2.20.0 to 2.20.1 ([#6](https://github.com/4cloudguru/pipeline-task-core/issues/6)) ([f369025](https://github.com/4cloudguru/pipeline-task-core/commit/f369025e9095755985f016dee350d6eaf18097d6))


### Documentation

* move framework onboarding detail to the private repo ([d99de30](https://github.com/4cloudguru/pipeline-task-core/commit/d99de30efe07766faab61d7bdf75fdbf993374cf))


### Chores

* publish as @4cloudguru/pipeline-task-core on public npmjs ([77cad9a](https://github.com/4cloudguru/pipeline-task-core/commit/77cad9a3d559b1870df512b99b735c1fabaac948))
