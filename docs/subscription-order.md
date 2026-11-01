# Manual subscription order

In **账户 → account details → 订阅排序**, move the currently publishable proxies
up or down and save. The same account's OpenClash/Mihomo proxy selection group
uses that order after the client refreshes its subscription. The link-list
format uses the same relative order for the proxy kinds it supports. `DIRECT`
remains last. Internal chain dependencies stay attached to their original proxy.

Names are display-only. Order is keyed by the existing native credential and
protocol, route ID or client-chain ID. Saving changes only account presentation
data in the existing encrypted `business.json`; it does not project node plans,
advance account policy revisions, regenerate keys/tokens, edit routes or alter
traffic. Consistent controller backups already contain this business file.

The administrator-only `POST /v1/admin/subscription-order` reads the account's
actual published inventory with `{ "accountId": "account-example" }`. It returns
`revision` as a decimal string, a metadata-only `inventory` fingerprint, and
`items` containing stable IDs, names, kinds and protocols, never connection keys
or subscription URLs. Saving adds `expectedRevision`, that `inventory`, and an
`ids` array containing each currently visible item exactly once. Stale revisions,
changed publication inventories, duplicates and foreign IDs are refused.

Existing quota, availability, authorization and runtime publication gates are
unchanged. Temporarily unavailable IDs retain their saved positions but never
become publishable because they appear in the order. Newly publishable proxies
without a saved position append in the existing default order. An absent order
keeps the current default. Re-read explicitly after a conflict; saving does not
silently overwrite another administrator's changes.
