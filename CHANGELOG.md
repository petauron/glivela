# Changelog

## [0.1.0-alpha.141](https://github.com/petauron/glivela/compare/v0.1.0-alpha.140...v0.1.0-alpha.141) (2026-11-13)


### Features

* **chains:** support exact private IPv4 client links ([#138](https://github.com/petauron/glivela/issues/138)) ([0630560](https://github.com/petauron/glivela/commit/0630560ce3c81cc6cc093e136aa639e3d318411d))

## [0.1.0-alpha.140](https://github.com/petauron/glivela/compare/v0.1.0-alpha.139...v0.1.0-alpha.140) (2026-11-13)


### Features

* safely add an isolated role to an existing native node ([#74](https://github.com/petauron/glivela/issues/74)) ([61d3b8c](https://github.com/petauron/glivela/commit/61d3b8c4a8869d64b418130855b257697c1e22ac))


### Bug Fixes

* **subscription:** use Taiwan flag for TW display prefix ([#135](https://github.com/petauron/glivela/issues/135)) ([00c9c2d](https://github.com/petauron/glivela/commit/00c9c2dd35be349bc592e3a22f5225dc82cba62f))

## [0.1.0-alpha.139](https://github.com/petauron/glivela/compare/v0.1.0-alpha.138...v0.1.0-alpha.139) (2026-11-13)


### Bug Fixes

* **network:** isolate gate cleanup by destination port ([226b2e6](https://github.com/petauron/glivela/commit/226b2e61fa55f20704bcffe1a1dafd0c2b54cbd3))

## [0.1.0-alpha.138](https://github.com/petauron/glivela/compare/v0.1.0-alpha.137...v0.1.0-alpha.138) (2026-11-13)


### Features

* **routes:** retain three-hop SS2022 paths in server forwarding ([#130](https://github.com/petauron/glivela/issues/130)) ([9c870c9](https://github.com/petauron/glivela/commit/9c870c9cd223ded440d3fc1c4155a1f61a8ac7d0))

## [0.1.0-alpha.137](https://github.com/petauron/glivela/compare/v0.1.0-alpha.136...v0.1.0-alpha.137) (2026-11-13)


### Bug Fixes

* **routes:** retry one timed-out startup identity proof ([#127](https://github.com/petauron/glivela/issues/127)) ([5f6b4ab](https://github.com/petauron/glivela/commit/5f6b4abb4b9e4ef35990df612c56d7de6ff2df8c))

## [0.1.0-alpha.136](https://github.com/petauron/glivela/compare/v0.1.0-alpha.135...v0.1.0-alpha.136) (2026-11-12)


### Bug Fixes

* **routes:** publish bound SS2022 server listeners end to end ([#125](https://github.com/petauron/glivela/issues/125)) ([b071dc1](https://github.com/petauron/glivela/commit/b071dc13079681c6593d01e04a8a877334fa9353))

## [0.1.0-alpha.135](https://github.com/petauron/glivela/compare/v0.1.0-alpha.134...v0.1.0-alpha.135) (2026-11-12)


### Bug Fixes

* **routes:** admit canonical public IPv6 entry peers ([#123](https://github.com/petauron/glivela/issues/123)) ([b8b93f9](https://github.com/petauron/glivela/commit/b8b93f906e0e1a08a85e615352ff2c3a7a7c3aac))

## [0.1.0-alpha.134](https://github.com/petauron/glivela/compare/v0.1.0-alpha.133...v0.1.0-alpha.134) (2026-11-12)


### Features

* **routes:** reuse enrolled public SS2022 listeners for server forwarding ([#121](https://github.com/petauron/glivela/issues/121)) ([1da4f8b](https://github.com/petauron/glivela/commit/1da4f8b226e27dc3bdb51eb997aa78e55ab87544))

## [0.1.0-alpha.133](https://github.com/petauron/glivela/compare/v0.1.0-alpha.132...v0.1.0-alpha.133) (2026-11-12)


### Bug Fixes

* **control:** authorize independently enrolled server landings ([bc96bc5](https://github.com/petauron/glivela/commit/bc96bc5a5538ac968d91a90da319245250e7d0f0))

## [0.1.0-alpha.132](https://github.com/petauron/glivela/compare/v0.1.0-alpha.131...v0.1.0-alpha.132) (2026-11-12)


### Bug Fixes

* **retirement:** preserve non-target history and service file owners ([#117](https://github.com/petauron/glivela/issues/117)) ([a2a8b1b](https://github.com/petauron/glivela/commit/a2a8b1ba8e0f50a1b8aed9257cb66e47c9cd5a85))

## [0.1.0-alpha.131](https://github.com/petauron/glivela/compare/v0.1.0-alpha.130...v0.1.0-alpha.131) (2026-11-12)


### Performance Improvements

* **control:** reduce native inspection and speed wake overhead ([#115](https://github.com/petauron/glivela/issues/115)) ([68b7074](https://github.com/petauron/glivela/commit/68b70746dc6d6ad65b3138bd13effa32a74ec8d5)), closes [#108](https://github.com/petauron/glivela/issues/108)

## [0.1.0-alpha.130](https://github.com/petauron/glivela/compare/v0.1.0-alpha.129...v0.1.0-alpha.130) (2026-11-12)


### Bug Fixes

* **retirement:** remove diagnostic history for retired pairs ([fda3b39](https://github.com/petauron/glivela/commit/fda3b39382b9a4bbf09d0f06409c993d66ed66e5))

## [0.1.0-alpha.129](https://github.com/petauron/glivela/compare/v0.1.0-alpha.128...v0.1.0-alpha.129) (2026-11-12)


### Bug Fixes

* **retirement:** allow creation of a new redaction audit ([6572ea8](https://github.com/petauron/glivela/commit/6572ea88a831f21f58638e044efdc098bccbcec5))

## [0.1.0-alpha.128](https://github.com/petauron/glivela/compare/v0.1.0-alpha.127...v0.1.0-alpha.128) (2026-11-12)


### Bug Fixes

* **retirement:** purge expired host history from retained archives ([#109](https://github.com/petauron/glivela/issues/109)) ([9fb7c9f](https://github.com/petauron/glivela/commit/9fb7c9f69089e5681a4160d42dc66cc74cea75b8))

## [0.1.0-alpha.127](https://github.com/petauron/glivela/compare/v0.1.0-alpha.126...v0.1.0-alpha.127) (2026-11-12)


### Bug Fixes

* **retirement:** clear volatile diagnostics by enrolled certificate ([#107](https://github.com/petauron/glivela/issues/107)) ([47cc65e](https://github.com/petauron/glivela/commit/47cc65e027299b99a08f988360bdfffaf29633bf))
* **retirement:** purge disabled route secrets without resetting shared usage ([#106](https://github.com/petauron/glivela/issues/106)) ([a666138](https://github.com/petauron/glivela/commit/a66613876365603fb63b8601cdb4ba69935f5abb))
* **retirement:** revoke and purge explicitly returned landings ([#104](https://github.com/petauron/glivela/issues/104)) ([6eb3b4b](https://github.com/petauron/glivela/commit/6eb3b4b72e1702a08b0c50814e29f026409d0bdc))

## [0.1.0-alpha.126](https://github.com/petauron/glivela/compare/v0.1.0-alpha.125...v0.1.0-alpha.126) (2026-11-11)


### Bug Fixes

* **control:** skip unchanged traffic checkpoint writes ([ff5bf3a](https://github.com/petauron/glivela/commit/ff5bf3a4b758469fa6341beb525738cf9b874098))

## [0.1.0-alpha.125](https://github.com/petauron/glivela/compare/v0.1.0-alpha.124...v0.1.0-alpha.125) (2026-11-11)


### Bug Fixes

* **control:** authenticate managed public forwarding through node mTLS ([5cb58cb](https://github.com/petauron/glivela/commit/5cb58cb054b0ca9c81fa99855063d6cab6ea470a))

## [0.1.0-alpha.124](https://github.com/petauron/glivela/compare/v0.1.0-alpha.123...v0.1.0-alpha.124) (2026-11-11)


### Bug Fixes

* **control:** preserve administrator network settings on reenrollment ([#97](https://github.com/petauron/glivela/issues/97)) ([9878712](https://github.com/petauron/glivela/commit/9878712f56a5f7a3f12b56046ca6e670ab1096a1))

## [0.1.0-alpha.123](https://github.com/petauron/glivela/compare/v0.1.0-alpha.122...v0.1.0-alpha.123) (2026-11-11)


### Features

* **routes:** reuse shared public SS2022 listener for server forwarding ([#95](https://github.com/petauron/glivela/issues/95)) ([3547680](https://github.com/petauron/glivela/commit/3547680e0755848e45144eb64aaf92b14778db55))

## [0.1.0-alpha.122](https://github.com/petauron/glivela/compare/v0.1.0-alpha.121...v0.1.0-alpha.122) (2026-11-11)


### Bug Fixes

* invalidate inactive pending route checks on restart ([#92](https://github.com/petauron/glivela/issues/92)) ([13bc632](https://github.com/petauron/glivela/commit/13bc632c518c68119ddcc5ec9eb9746815c992c4))

## [0.1.0-alpha.121](https://github.com/petauron/glivela/compare/v0.1.0-alpha.120...v0.1.0-alpha.121) (2026-11-10)


### Features

* bind client exits within one landing instance ([#90](https://github.com/petauron/glivela/issues/90)) ([7cbd8c1](https://github.com/petauron/glivela/commit/7cbd8c14edc0934bf27a3218c5a8b0224218774a))

## [0.1.0-alpha.120](https://github.com/petauron/glivela/compare/v0.1.0-alpha.119...v0.1.0-alpha.120) (2026-11-10)


### Features

* isolate client-only landings on shared hosts ([#88](https://github.com/petauron/glivela/issues/88)) ([99fb51a](https://github.com/petauron/glivela/commit/99fb51ad4e4b8de1d0f29a189b3b9dfdbb5f572f))

## [0.1.0-alpha.119](https://github.com/petauron/glivela/compare/v0.1.0-alpha.118...v0.1.0-alpha.119) (2026-11-10)


### Bug Fixes

* show bound host names when creating routes ([8cd837b](https://github.com/petauron/glivela/commit/8cd837bf2dbdfc582173896183da527ccc229f9d))

## [0.1.0-alpha.118](https://github.com/petauron/glivela/compare/v0.1.0-alpha.117...v0.1.0-alpha.118) (2026-11-10)


### Features

* support IPv4 entry to IPv6 relay chains ([489da09](https://github.com/petauron/glivela/commit/489da0966ea3a47d42a4cf2b9ce5338f34e092ef)), closes [#80](https://github.com/petauron/glivela/issues/80)
* support three-hop client chains ([0c0f55c](https://github.com/petauron/glivela/commit/0c0f55c23204c17101df975295b241d035ab52cb)), closes [#80](https://github.com/petauron/glivela/issues/80)


### Bug Fixes

* show unconfirmed three-hop runtime state ([aa4a7d7](https://github.com/petauron/glivela/commit/aa4a7d74eef055973739fc91d0ce874ea7b70576)), closes [#80](https://github.com/petauron/glivela/issues/80)

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
