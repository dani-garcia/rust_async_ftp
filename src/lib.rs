//! ftp is an FTP client written in Rust.
//!
//! ### Usage
//!
//! Here is a basic usage example:
//!
//! ```rust,no_run
//! use async_ftp::FtpStream;
//! async {
//!   let mut ftp_stream = FtpStream::connect("172.25.82.139:21").await.unwrap_or_else(|err|
//!       panic!("{}", err)
//!   );
//!   let _ = ftp_stream.quit();
//! };
//! ```
//!
//! ### FTPS
//!
//! The client supports FTPS on demand. To enable it the client should be
//! compiled with feature `openssl` enabled what requires
//! [openssl](https://crates.io/crates/openssl) dependency.
//!
//! The client uses explicit mode for connecting FTPS what means you should
//! connect the server as usually and then switch to the secure mode (TLS is used).
//! For better security it's the good practice to switch to the secure mode
//! before authentication.
//!
//! ### FTPS Usage
//!
//! ```rust,no_run
//! use std::convert::TryFrom;
//! use std::path::Path;
//! use async_ftp::FtpStream;
//! use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerName};
//!
//! async {
//!   let ftp_stream = FtpStream::connect("172.25.82.139:21").await.unwrap();
//!   
//!   let mut root_store = RootCertStore::empty();
//!   // root_store.add_pem_file(...);
//!   let conf = ClientConfig::builder().with_safe_defaults().with_root_certificates(root_store).with_no_client_auth();
//!   let domain = ServerName::try_from("www.cert-domain.com").expect("invalid DNS name");
//!
//!   // Switch to the secure mode
//!   let mut ftp_stream = ftp_stream.into_secure(conf, domain).await.unwrap();
//!   ftp_stream.login("anonymous", "anonymous").await.unwrap();
//!   // Do other secret stuff
//!   // Switch back to the insecure mode (if required)
//!   let mut ftp_stream = ftp_stream.into_insecure().await.unwrap();
//!   // Do all public stuff
//!   let _ = ftp_stream.quit().await;
//! };
//! ```
//!

mod data_stream;
mod ftp;
pub mod status;
pub mod types;

pub use self::data_stream::DataStream;
pub use self::ftp::FtpStream;
pub use self::types::FtpError;
