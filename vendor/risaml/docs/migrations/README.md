# Migration guides

These guides describe the changes consumers need to make when upgrading
between breaking pre-1.0 releases of `risaml` and, up to 0.5, of `saml-rs`,
the upstream crate risaml was forked from. The guides up to 0.5 keep their
original saml-rs prose; their code paths use today's `risaml::` name. The
[changelog](../../CHANGELOG.md) remains the complete record of changes in each
release.

## Available guides

- [`0.2` to `0.3`](0.2-to-0.3.md)
- [`0.3` to `0.4`](0.3-to-0.4.md)
- [`0.4` to `0.5`](0.4-to-0.5.md)
- [saml-rs `0.5` to risaml `0.6`](0.5-to-0.6.md)
- [risaml `0.6` to `0.7`](0.6-to-0.7.md)

## Adding a guide

Name each guide after its version boundary, such as `0.2-to-0.3.md`. Cover
upgrades from the latest patch of the source minor release to the target minor
release, and focus on required code changes, changed runtime behavior, feature
flags, and MSRV changes.
