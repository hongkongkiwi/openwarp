# lber 0.4.2, vendored

This is the MIT-licensed `lber` crate (from the `ldap3` project, see
`LICENSE`), copied unchanged except for one addition in `src/parse.rs`:

- `parse_tag` descends recursively through constructed BER elements. A peer
  could send a deeply nested message and exhaust the thread stack, which
  aborts the process rather than unwinding. The parser now counts depth and
  refuses more than 64 nested constructed elements with
  `ErrorKind::TooLarge`. Real LDAP messages nest fewer than ten deep.

A regression test in the same file builds 100 nested sequences and asserts
that parsing returns an error.

The workspace root patches `lber` to this path so `ldap3` uses the capped
parser. Remove the `[patch.crates-io]` entry and this directory once an
upstream `lber` release carries a depth limit.
