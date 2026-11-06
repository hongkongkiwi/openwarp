//! Shared connector code used by the server and by the customer-run sync
//! runner. The runner is a separate binary so provider credentials and
//! plaintext never have to enter the server process.
pub mod integrations;
