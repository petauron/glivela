# Changelog

## [0.1.0-alpha.117](https://github.com/petauron/glivela/compare/v0.1.0-alpha.116...v0.1.0-alpha.117) (2026-11-10)


### Bug Fixes

* **control:** support explicit userspace private-network dialing ([#78](https://github.com/petauron/glivela/issues/78)) ([333c6b8](https://github.com/petauron/glivela/commit/333c6b830f8630804cd6938163fa26d071e62add))

## [0.1.0-alpha.116](https://github.com/petauron/glivela/compare/v0.1.0-alpha.115...v0.1.0-alpha.116) (2026-11-10)


### Bug Fixes

* **subscription:** configure landing region labels without changing routes ([#76](https://github.com/petauron/glivela/issues/76)) ([8e81af4](https://github.com/petauron/glivela/commit/8e81af4195a4531e9cdc6391a92f074df96faf59))

## [0.1.0-alpha.115](https://github.com/petauron/glivela/compare/v0.1.0-alpha.114...v0.1.0-alpha.115) (2026-11-08)


### Features

* **control:** configure path MTU per destination ([#30](https://github.com/petauron/glivela/issues/30)) ([e4997c2](https://github.com/petauron/glivela/commit/e4997c26567994dfd3211762b06b8ea9cb515d19))
* **panel:** restore node egress controls ([#57](https://github.com/petauron/glivela/issues/57)) ([821cba5](https://github.com/petauron/glivela/commit/821cba5efb3f204d03d6455bdb3bebc59fe12869))
* **runtime:** support OpenRC native nodes ([#55](https://github.com/petauron/glivela/issues/55)) ([50447b6](https://github.com/petauron/glivela/commit/50447b6b4e30d2165f3c145caa1e8e09a2f23fd5))
* **subscription:** add manual proxy ordering ([#26](https://github.com/petauron/glivela/issues/26)) ([b313733](https://github.com/petauron/glivela/commit/b31373380c6bf5c1644adad7f6255476809017b4))


### Bug Fixes

* **control:** allow activation retry for an unused fresh endpoint ([#48](https://github.com/petauron/glivela/issues/48)) ([9570096](https://github.com/petauron/glivela/commit/95700962a7cc8f27513efbda538122848b1b81c3))
* **control:** correct IPv6 client-chain latency and route labels ([#52](https://github.com/petauron/glivela/issues/52)) ([7949578](https://github.com/petauron/glivela/commit/79495781948d41046513f07cdbfabe04d7a7ad66))
* **control:** expire obsolete landing route checks ([#28](https://github.com/petauron/glivela/issues/28)) ([03de2d9](https://github.com/petauron/glivela/commit/03de2d93611d1bb8436dc350cea64870d1718767))
* **control:** preserve owned identity during legacy entry handover ([fa42792](https://github.com/petauron/glivela/commit/fa42792d0270127e32beb80dcbd99b8b9cb80125))
* **control:** recognize systemd-resolved ownership during entry staging ([f72fe6c](https://github.com/petauron/glivela/commit/f72fe6cdaa694dcd8d6064df9bcc882244124b0c))
* **control:** recover invalid initial local REALITY targets ([#59](https://github.com/petauron/glivela/issues/59)) ([7dcd307](https://github.com/petauron/glivela/commit/7dcd3079756e409909cc667460410c257201b81d))
* **control:** reopen partial entry inventories after restart ([#46](https://github.com/petauron/glivela/issues/46)) ([ef0f40a](https://github.com/petauron/glivela/commit/ef0f40a4a575f7cc9d653b249fd9d98240c7d919))
* **egress:** handle unreachable IP families in automatic TCP dialing ([#54](https://github.com/petauron/glivela/issues/54)) ([e1b3224](https://github.com/petauron/glivela/commit/e1b32241acbedfb05609a49745fdd1fd9171123e))
* preserve operator configuration across release handoff ([#23](https://github.com/petauron/glivela/issues/23)) ([202ca84](https://github.com/petauron/glivela/commit/202ca841334688f030c5b4c62173ff8bae9c89a5))
* recover landing firewall after public IP changes ([#34](https://github.com/petauron/glivela/issues/34)) ([461cfb6](https://github.com/petauron/glivela/commit/461cfb674d166de8211cede36b415a33f12e83d3))
* resolve IPv6 landing DNS through its fixed IPv6 exit ([d474679](https://github.com/petauron/glivela/commit/d47467951a08edd744d88f997113ab3cda25640b))
* resolve pinned runtime assets through the official API ([#71](https://github.com/petauron/glivela/issues/71)) ([87f0a9d](https://github.com/petauron/glivela/commit/87f0a9d7807c917d6f7e3f8d0a1c0af7de83bede))
* select IPv6 DNS for IPv6-only entries ([#64](https://github.com/petauron/glivela/issues/64)) ([555425f](https://github.com/petauron/glivela/commit/555425fa8f9d6807253b078fcaefb2c31ca47bd5))
* **subscription:** align labels and default order ([e7714d0](https://github.com/petauron/glivela/commit/e7714d0d321a091f91f564546fa93abf66b6ab97))
* support explicit IPv6-only client landings ([#69](https://github.com/petauron/glivela/issues/69)) ([b84073a](https://github.com/petauron/glivela/commit/b84073a80c9e25d28064763935a3cabed9c0328b))
* sync managed host display names ([b67e286](https://github.com/petauron/glivela/commit/b67e28603aa38a80f80f660dbbc99de2d0be1d62)), closes [#36](https://github.com/petauron/glivela/issues/36)
* 支持独立落地节点关联主机名称 ([00b39a1](https://github.com/petauron/glivela/commit/00b39a182a9a388efaf3546580fa4b75c8d2a9b4))

## [0.1.0-alpha.114](https://github.com/petauron/glivela/compare/v0.1.0-alpha.113...v0.1.0-alpha.114) (2026-11-08)


### Bug Fixes

* support explicit IPv6-only client landings ([#69](https://github.com/petauron/glivela/issues/69)) ([b84073a](https://github.com/petauron/glivela/commit/b84073a80c9e25d28064763935a3cabed9c0328b))

## [0.1.0-alpha.113](https://github.com/petauron/glivela/compare/v0.1.0-alpha.112...v0.1.0-alpha.113) (2026-11-08)


### Bug Fixes

* resolve IPv6 landing DNS through its fixed IPv6 exit ([d474679](https://github.com/petauron/glivela/commit/d47467951a08edd744d88f997113ab3cda25640b))

## [0.1.0-alpha.112](https://github.com/petauron/glivela/compare/v0.1.0-alpha.111...v0.1.0-alpha.112) (2026-11-08)


### Bug Fixes

* select IPv6 DNS for IPv6-only entries ([#64](https://github.com/petauron/glivela/issues/64)) ([555425f](https://github.com/petauron/glivela/commit/555425fa8f9d6807253b078fcaefb2c31ca47bd5))

## [0.1.0-alpha.111](https://github.com/petauron/glivela/compare/v0.1.0-alpha.110...v0.1.0-alpha.111) (2026-11-06)


### Bug Fixes

* **subscription:** align labels and default order ([e7714d0](https://github.com/petauron/glivela/commit/e7714d0d321a091f91f564546fa93abf66b6ab97))

## [0.1.0-alpha.110](https://github.com/petauron/glivela/compare/v0.1.0-alpha.109...v0.1.0-alpha.110) (2026-11-06)


### Features

* **panel:** restore node egress controls ([#57](https://github.com/petauron/glivela/issues/57)) ([821cba5](https://github.com/petauron/glivela/commit/821cba5efb3f204d03d6455bdb3bebc59fe12869))
* **runtime:** support OpenRC native nodes ([#55](https://github.com/petauron/glivela/issues/55)) ([50447b6](https://github.com/petauron/glivela/commit/50447b6b4e30d2165f3c145caa1e8e09a2f23fd5))


### Bug Fixes

* **control:** correct IPv6 client-chain latency and route labels ([#52](https://github.com/petauron/glivela/issues/52)) ([7949578](https://github.com/petauron/glivela/commit/79495781948d41046513f07cdbfabe04d7a7ad66))
* **control:** recover invalid initial local REALITY targets ([#59](https://github.com/petauron/glivela/issues/59)) ([7dcd307](https://github.com/petauron/glivela/commit/7dcd3079756e409909cc667460410c257201b81d))
* **egress:** handle unreachable IP families in automatic TCP dialing ([#54](https://github.com/petauron/glivela/issues/54)) ([e1b3224](https://github.com/petauron/glivela/commit/e1b32241acbedfb05609a49745fdd1fd9171123e))

## [0.1.0-alpha.109](https://github.com/petauron/glivela/compare/v0.1.0-alpha.108...v0.1.0-alpha.109) (2026-11-04)


### Bug Fixes

* **control:** allow activation retry for an unused fresh endpoint ([#48](https://github.com/petauron/glivela/issues/48)) ([9570096](https://github.com/petauron/glivela/commit/95700962a7cc8f27513efbda538122848b1b81c3))

## [0.1.0-alpha.108](https://github.com/petauron/glivela/compare/v0.1.0-alpha.107...v0.1.0-alpha.108) (2026-11-03)


### Bug Fixes

* **control:** reopen partial entry inventories after restart ([#46](https://github.com/petauron/glivela/issues/46)) ([ef0f40a](https://github.com/petauron/glivela/commit/ef0f40a4a575f7cc9d653b249fd9d98240c7d919))

## [0.1.0-alpha.107](https://github.com/petauron/glivela/compare/v0.1.0-alpha.106...v0.1.0-alpha.107) (2026-11-03)


### Bug Fixes

* **control:** recognize systemd-resolved ownership during entry staging ([f72fe6c](https://github.com/petauron/glivela/commit/f72fe6cdaa694dcd8d6064df9bcc882244124b0c))

## [0.1.0-alpha.106](https://github.com/petauron/glivela/compare/v0.1.0-alpha.105...v0.1.0-alpha.106) (2026-11-03)


### Bug Fixes

* 支持独立落地节点关联主机名称 ([00b39a1](https://github.com/petauron/glivela/commit/00b39a182a9a388efaf3546580fa4b75c8d2a9b4))

## [0.1.0-alpha.105](https://github.com/petauron/glivela/compare/v0.1.0-alpha.104...v0.1.0-alpha.105) (2026-11-03)


### Bug Fixes

* **control:** preserve owned identity during legacy entry handover ([fa42792](https://github.com/petauron/glivela/commit/fa42792d0270127e32beb80dcbd99b8b9cb80125))

## [0.1.0-alpha.104](https://github.com/petauron/glivela/compare/v0.1.0-alpha.103...v0.1.0-alpha.104) (2026-11-03)


### Bug Fixes

* sync managed host display names ([b67e286](https://github.com/petauron/glivela/commit/b67e28603aa38a80f80f660dbbc99de2d0be1d62)), closes [#36](https://github.com/petauron/glivela/issues/36)

## [0.1.0-alpha.103](https://github.com/petauron/glivela/compare/v0.1.0-alpha.102...v0.1.0-alpha.103) (2026-11-02)


### Bug Fixes

* recover landing firewall after public IP changes ([#34](https://github.com/petauron/glivela/issues/34)) ([461cfb6](https://github.com/petauron/glivela/commit/461cfb674d166de8211cede36b415a33f12e83d3))

## [0.1.0-alpha.102](https://github.com/petauron/glivela/compare/v0.1.0-alpha.101...v0.1.0-alpha.102) (2026-11-01)


### Features

* **control:** configure path MTU per destination ([#30](https://github.com/petauron/glivela/issues/30)) ([e4997c2](https://github.com/petauron/glivela/commit/e4997c26567994dfd3211762b06b8ea9cb515d19))

## [0.1.0-alpha.101](https://github.com/petauron/glivela/compare/v0.1.0-alpha.100...v0.1.0-alpha.101) (2026-11-01)


### Bug Fixes

* **control:** expire obsolete landing route checks ([#28](https://github.com/petauron/glivela/issues/28)) ([03de2d9](https://github.com/petauron/glivela/commit/03de2d93611d1bb8436dc350cea64870d1718767))

## [0.1.0-alpha.100](https://github.com/petauron/glivela/compare/v0.1.0-alpha.99...v0.1.0-alpha.100) (2026-11-01)


### Features

* **subscription:** add manual proxy ordering ([#26](https://github.com/petauron/glivela/issues/26)) ([b313733](https://github.com/petauron/glivela/commit/b31373380c6bf5c1644adad7f6255476809017b4))

## [0.1.0-alpha.99](https://github.com/petauron/glivela/compare/v0.1.0-alpha.98...v0.1.0-alpha.99) (2026-11-01)


### Bug Fixes

* preserve operator configuration across release handoff ([#23](https://github.com/petauron/glivela/issues/23)) ([202ca84](https://github.com/petauron/glivela/commit/202ca841334688f030c5b4c62173ff8bae9c89a5))

## 0.1.0-alpha.98

- Consolidated source baseline for the controller, native nodes and independent UI.
- Public examples use synthetic labels; operator-specific naming aliases and
  historical development/acceptance records are not part of this source baseline.

Release Please maintains subsequent release entries.
