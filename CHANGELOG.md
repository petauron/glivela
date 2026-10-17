# Changelog

## [0.1.0-alpha.23](https://github.com/petauron/glivela/compare/v0.1.0-alpha.22...v0.1.0-alpha.23) (2026-10-17)


### Bug Fixes

* refresh bundled landing latency provider and cover stalled streams ([f29fdbb](https://github.com/petauron/glivela/commit/f29fdbb2f2385abf9bb4dd3104cc89d27c5a9524))

## [0.1.0-alpha.22](https://github.com/petauron/glivela/compare/v0.1.0-alpha.21...v0.1.0-alpha.22) (2026-10-17)


### Bug Fixes

* **glivela:** complete canonical source and UI artifact naming ([fb82981](https://github.com/petauron/glivela/commit/fb829816747807e8a3f77030c2e475583b2f4a08))
* **glivela:** migrate source and UI naming while preserving runtime identities ([#48](https://github.com/petauron/glivela/issues/48)) ([1ea7a12](https://github.com/petauron/glivela/commit/1ea7a12d24631c44bdf8d7960d51b717f893e006))
* **senulun:** pin canonical monitoring UI integration ([9c152e6](https://github.com/petauron/glivela/commit/9c152e64e1c1b162349e4aa442a79f21947122ce))
* **ui:** verify the reviewed centered Sheet layout after source pin update ([1de6932](https://github.com/petauron/glivela/commit/1de6932f0ffb6619e0eee29adc040afbdedb5233))

## [0.1.0-alpha.21](https://github.com/petauron/glivela/compare/v0.1.0-alpha.20...v0.1.0-alpha.21) (2026-10-17)


### Bug Fixes

* **ui:** sort node quality by score and restore vertical scrolling ([#46](https://github.com/petauron/glivela/issues/46)) ([aae951f](https://github.com/petauron/glivela/commit/aae951f1d2cad0cf81ae64102f4f3e5973d43553))

## [0.1.0-alpha.20](https://github.com/petauron/glivela/compare/v0.1.0-alpha.19...v0.1.0-alpha.20) (2026-10-17)


### Bug Fixes

* **routes:** expose lazy per-leg health diagnostics ([9ea520d](https://github.com/petauron/glivela/commit/9ea520d19d7d4aae6ef9e0c82fc33b04ede7aed0))
* **ui:** explain IP scores and fit node comparison columns ([#17](https://github.com/petauron/glivela/issues/17)) ([e4950e2](https://github.com/petauron/glivela/commit/e4950e262df3cdfcc114ec8c961c0d9950ddef3d))
* **ui:** include shared component styles in application bundle ([#45](https://github.com/petauron/glivela/issues/45)) ([ecaf8ef](https://github.com/petauron/glivela/commit/ecaf8ef1c730759935b466d10c6f7755d72424b8))

## [0.1.0-alpha.19](https://github.com/petauron/glivela/compare/v0.1.0-alpha.18...v0.1.0-alpha.19) (2026-10-13)


### Bug Fixes

* **deps:** patch source-map-js denial-of-service vulnerability ([01c606c](https://github.com/petauron/glivela/commit/01c606c1995dad203af712280e511faf2a170608))
* **ui:** remove vulnerable component CLI dependencies ([3208df4](https://github.com/petauron/glivela/commit/3208df40990a2271c561569784d18395ff5dd6d8))

## [0.1.0-alpha.18](https://github.com/petauron/glivela/compare/v0.1.0-alpha.17...v0.1.0-alpha.18) (2026-10-13)


### Bug Fixes

* **subscription:** preserve home route names when adding IPv4 exits ([0ac05e9](https://github.com/petauron/glivela/commit/0ac05e9725810d4cb88b7ba678f03598cea0625a))

## [0.1.0-alpha.17](https://github.com/petauron/glivela/compare/v0.1.0-alpha.16...v0.1.0-alpha.17) (2026-10-13)


### Features

* **routing:** add strict IPv6 and IPv4 composite exits ([#34](https://github.com/petauron/glivela/issues/34)) ([ba1d641](https://github.com/petauron/glivela/commit/ba1d6417dabb7990131effbb49f78f64c4e8dff4))


### Bug Fixes

* **routing:** use official Xray for IPv6 and IPv4 composites ([264e9a1](https://github.com/petauron/glivela/commit/264e9a110b2651f3dd2b62ddc72de46fb3d1aaed))
* **runtime:** validate composite capabilities before configuration switch ([8976ef0](https://github.com/petauron/glivela/commit/8976ef02d290bf66bb7d855fb710ae8fb79a8e90))

## [0.1.0-alpha.16](https://github.com/petauron/glivela/compare/v0.1.0-alpha.15...v0.1.0-alpha.16) (2026-10-12)


### Features

* add optional landing subscription name suffix ([#23](https://github.com/petauron/glivela/issues/23)) ([0323107](https://github.com/petauron/glivela/commit/03231073a667b28c68b4f0f4e6233a3ac6acf29e))
* complete Meridian protocol and migration core ([#1](https://github.com/petauron/glivela/issues/1)) ([d8362f2](https://github.com/petauron/glivela/commit/d8362f2a7ad55833208780eeacaf9fbbfd6fbfe0))
* enforce strict native egress address families ([#21](https://github.com/petauron/glivela/issues/21)) ([17e0820](https://github.com/petauron/glivela/commit/17e08203e08b6cc64a29941b8f8c52d0f1a22b06))
* establish Meridian domain core ([9cf41f6](https://github.com/petauron/glivela/commit/9cf41f6aa85f6dc800d8a6e3599177b737f98103))
* rebrand Meridian as Glivela with stable installation identity ([#31](https://github.com/petauron/glivela/issues/31)) ([2078a65](https://github.com/petauron/glivela/commit/2078a653e8eb27cbcfd5d7f068fb33f6323c8d2d))
* **runtime:** bind REALITY to an explicit private host backend ([#18](https://github.com/petauron/glivela/issues/18)) ([78a6f81](https://github.com/petauron/glivela/commit/78a6f8181ae7a380a5bd2c108784578bf5ffeeb0))
* **subscription:** label routes with landing region ([#6](https://github.com/petauron/glivela/issues/6)) ([2806d80](https://github.com/petauron/glivela/commit/2806d807639a569eb6f47f143d73fc8c87082bdb))
* **ui:** make Meridian node selection comparable ([#14](https://github.com/petauron/glivela/issues/14)) ([ee5fae3](https://github.com/petauron/glivela/commit/ee5fae3400c2cbf3f0effa8c58d3aa5a14f45c95))
* **ui:** show route traffic and Pulse server budgets ([#22](https://github.com/petauron/glivela/issues/22)) ([be695ac](https://github.com/petauron/glivela/commit/be695ac5370d1912213bb4f960d9f78efb41be45))
* **ui:** simplify Meridian link speed tests ([#9](https://github.com/petauron/glivela/issues/9)) ([fcb987d](https://github.com/petauron/glivela/commit/fcb987d07a7a7aaa2799ae2d0666ed6255b8a8d3))


### Bug Fixes

* accept omitted zero Xray usage counters ([#2](https://github.com/petauron/glivela/issues/2)) ([15d485d](https://github.com/petauron/glivela/commit/15d485d8cdd0f18eea83b6f7505c017eab707fbb))
* clarify landing labels and preserve circuit types ([#27](https://github.com/petauron/glivela/issues/27)) ([62cd660](https://github.com/petauron/glivela/commit/62cd660b5e5e6957095ee4b7864e359712f1b41a))
* compact subscription circuit and landing names ([#26](https://github.com/petauron/glivela/issues/26)) ([a3a0678](https://github.com/petauron/glivela/commit/a3a067840ff8e9d7bd3eb630b841c10d22044029))
* migrate canonical source repository to glivela ([5566ae3](https://github.com/petauron/glivela/commit/5566ae3b11c9cc8eb5ff7a75d91460463e29e48a))
* restore destination domains for IPv6 landing routes ([#3](https://github.com/petauron/glivela/issues/3)) ([8e19ce9](https://github.com/petauron/glivela/commit/8e19ce926ab013d8da97245321a2af9facb4565a))
* **subscription:** label landing routes with text ([#12](https://github.com/petauron/glivela/issues/12)) ([5cec83f](https://github.com/petauron/glivela/commit/5cec83fcb95f1573ff248fe902f3d9abb28a4189))
* **subscription:** mark landing exits with visible relay icon ([#11](https://github.com/petauron/glivela/issues/11)) ([a91217c](https://github.com/petauron/glivela/commit/a91217cc494d2452d3669a07b1411ac9ba2fbc3d))
* **ui:** adopt selected-node diagnostics in alpha.5 ([#8](https://github.com/petauron/glivela/issues/8)) ([6d4437c](https://github.com/petauron/glivela/commit/6d4437ce0b13834977d5d7a37e52186970334ad6))
* **ui:** align service availability in table columns ([#15](https://github.com/petauron/glivela/issues/15)) ([0f33cb7](https://github.com/petauron/glivela/commit/0f33cb7338f9327ea3ea387a2483050d956a1229))
* **ui:** distinguish unverified and expired link tests ([#20](https://github.com/petauron/glivela/issues/20)) ([3a22364](https://github.com/petauron/glivela/commit/3a22364156593e55ab460c27af71249b5e05dfdc))
* **ui:** improve node table and adopt IP2Location risk display ([#7](https://github.com/petauron/glivela/issues/7)) ([6c8001f](https://github.com/petauron/glivela/commit/6c8001ff8ac1ca0adc134135508b1e5c1ed7fd66))
* **ui:** keep link test table aligned on desktop ([#10](https://github.com/petauron/glivela/issues/10)) ([3e9ca01](https://github.com/petauron/glivela/commit/3e9ca013fc748b85c74d00da17fba2baff079868))
* **ui:** make Meridian bundle browser-safe ([fdb2e50](https://github.com/petauron/glivela/commit/fdb2e50ff592206020698b0ee070b9b40ea8b426))
* **ui:** replace Node environment in browser bundle ([1cdd574](https://github.com/petauron/glivela/commit/1cdd5745c1513cd0f012b9c7c80e96ce82ce1be2))
* **ui:** restore landing access after entry reenrollment ([#19](https://github.com/petauron/glivela/issues/19)) ([b499bcf](https://github.com/petauron/glivela/commit/b499bcfa7cf522a4fc2b031608770d766983060d))
* **ui:** simplify Meridian node selection and status ([#16](https://github.com/petauron/glivela/issues/16)) ([aa43856](https://github.com/petauron/glivela/commit/aa43856ea1cc2bcfbf39e32e7bcdd1931ee776ab))
