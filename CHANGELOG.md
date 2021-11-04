# Changelog

## 6.0.0
- Update tokio-rustls to 0.23
    - If you don't have the `secure` feature enabled, this change doesn't affect you
    - If you do have it enabled, the docs should explain the changes from `DnsName` to `ServerName`, and the setup of `ClientConfig`
## 5.1.0
- Add resume functionality
- Added function to get server welcome message.
- Use the peer address when the server responds with all zeroes like is the case with IPv6.
- Added some small tests for types.
- Make the test results clearer, using ? instead of asserting is_ok().
## 5.0.0
- Update to tokio 1.0.
## 4.0.4
- Minor bug in FtpStream::get.
## 4.0.2
- Make get_lines_from_stream work for unix newlines.
- Add test for list returning unix newlines.
## 4.0.1
- Drop data stream before waiting close code.
## 4.0.0
- Initial release with 2018 edition and tokio support.


## For versions 3.0 and below, check the original sync fork:
https://raw.githubusercontent.com/mattnenterprise/rust-ftp/master/CHANGELOG.md