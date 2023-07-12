//! FTP module.
use std::borrow::Cow;
use std::net::SocketAddr;
use std::string::String;

use chrono::offset::TimeZone;
use chrono::{DateTime, Utc};
use regex::Regex;

use tokio::io::{
    copy, AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader,
    BufWriter,
};
use tokio::net::{TcpStream, ToSocketAddrs};

#[cfg(feature = "secure")]
use tokio_rustls::{rustls::ClientConfig, rustls::ServerName, TlsConnector};

use crate::data_stream::DataStream;
use crate::status;
use crate::types::{FileType, FtpError, Line, Result};

lazy_static::lazy_static! {
    // This regex extracts IP and Port details from PASV command response.
    // The regex looks for the pattern (h1,h2,h3,h4,p1,p2).
    static ref PORT_RE: Regex = Regex::new(r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)").unwrap();

    // This regex extracts modification time from MDTM command response.
    static ref MDTM_RE: Regex = Regex::new(r"\b(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})\b").unwrap();

    // This regex extracts file size from SIZE command response.
    static ref SIZE_RE: Regex = Regex::new(r"\s+(\d+)\s*$").unwrap();
}

/// Stream to interface with the FTP server. This interface is only for the command stream.
pub struct FtpStream {
    reader: BufReader<DataStream>,
    #[cfg(feature = "secure")]
    ssl_cfg: Option<(ClientConfig, ServerName)>,
    welcome_msg: Option<String>,
}

impl FtpStream {
    /// Creates an FTP Stream.
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> Result<FtpStream> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(FtpError::ConnectionError)?;

        let mut ftp_stream = FtpStream {
            reader: BufReader::new(DataStream::Tcp(stream)),
            #[cfg(feature = "secure")]
            ssl_cfg: None,
            welcome_msg: None,
        };
        let result = ftp_stream.read_response(status::READY).await?;
        ftp_stream.welcome_msg = Some(result.1);

        Ok(ftp_stream)
    }

    /// Switch to a secure mode if possible, using a provided SSL configuration.
    /// This method does nothing if the connect is already secured.
    ///
    /// ## Panics
    ///
    /// Panics if the plain TCP connection cannot be switched to TLS mode.
    ///
    /// ## Example
    ///
    /// ```rust,no_run
    /// use std::convert::TryFrom;
    /// use std::path::Path;
    /// use async_ftp::FtpStream;
    /// use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerName};
    ///
    /// let mut root_store = RootCertStore::empty();
    /// // root_store.add_pem_file(...);
    /// let conf = ClientConfig::builder().with_safe_defaults().with_root_certificates(root_store).with_no_client_auth();
    /// let domain = ServerName::try_from("www.cert-domain.com").expect("invalid DNS name");
    /// async {
    ///   let mut ftp_stream = FtpStream::connect("172.25.82.139:21").await.unwrap();
    ///   let mut ftp_stream = ftp_stream.into_secure(conf, domain).await.unwrap();
    /// };
    /// ```
    #[cfg(feature = "secure")]
    pub async fn into_secure(mut self, config: ClientConfig, domain: ServerName) -> Result<FtpStream> {
        // Ask the server to start securing data.
        self.write_str("AUTH TLS\r\n").await?;
        self.read_response(status::AUTH_OK).await?;

        let connector: TlsConnector = std::sync::Arc::new(config.clone()).into();
        let stream = connector
            .connect(domain.clone(), self.reader.into_inner().into_tcp_stream())
            .await
            .map_err(|e| FtpError::SecureError(format!("{}", e)))?;

        let mut secured_ftp_tream = FtpStream {
            reader: BufReader::new(DataStream::Ssl(stream)),
            ssl_cfg: Some((config, domain)),
            welcome_msg: None,
        };
        // Set protection buffer size
        secured_ftp_tream.write_str("PBSZ 0\r\n").await?;
        secured_ftp_tream.read_response(status::COMMAND_OK).await?;
        // Change the level of data protectio to Private
        secured_ftp_tream.write_str("PROT P\r\n").await?;
        secured_ftp_tream.read_response(status::COMMAND_OK).await?;
        Ok(secured_ftp_tream)
    }

    /// Switch to insecure mode. If the connection is already
    /// insecure does nothing.
    ///
    /// ## Example
    ///
    /// ```rust,no_run
    /// use std::convert::TryFrom;
    /// use std::path::Path;
    /// use async_ftp::FtpStream;
    /// use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerName};
    ///
    /// let mut root_store = RootCertStore::empty();
    /// // root_store.add_pem_file(...);
    /// let conf = ClientConfig::builder().with_safe_defaults().with_root_certificates(root_store).with_no_client_auth();
    /// let domain = ServerName::try_from("www.cert-domain.com").expect("invalid DNS name");
    /// async {
    ///   let mut ftp_stream = FtpStream::connect("172.25.82.139:21").await.unwrap();
    ///   let mut ftp_stream = ftp_stream.into_secure(conf, domain).await.unwrap();
    ///   // Switch back to the insecure mode
    ///   let mut ftp_stream = ftp_stream.into_insecure().await.unwrap();
    ///   // Do all public things
    ///   let _ = ftp_stream.quit();
    /// };
    /// ```
    #[cfg(feature = "secure")]
    pub async fn into_insecure(mut self) -> Result<FtpStream> {
        // Ask the server to stop securing data
        self.write_str("CCC\r\n").await?;
        self.read_response(status::COMMAND_OK).await?;
        let plain_ftp_stream = FtpStream {
            reader: BufReader::new(DataStream::Tcp(self.reader.into_inner().into_tcp_stream())),
            ssl_cfg: None,
            welcome_msg: None,
        };
        Ok(plain_ftp_stream)
    }

    /// Execute command which send data back in a separate stream
    async fn data_command(&mut self, cmd: &str) -> Result<DataStream> {
        let addr = self.pasv().await?;
        self.write_str(cmd).await?;

        let stream = TcpStream::connect(addr)
            .await
            .map_err(FtpError::ConnectionError)?;

        #[cfg(feature = "secure")]
        match &self.ssl_cfg {
            Some((config, domain)) => {
                let connector: TlsConnector = std::sync::Arc::new(config.clone()).into();
                return connector
                    .connect(domain.to_owned(), stream)
                    .await
                    .map(|stream| DataStream::Ssl(stream))
                    .map_err(|e| FtpError::SecureError(format!("{}", e)));
            }
            _ => {}
        };

        Ok(DataStream::Tcp(stream))
    }

    /// Returns a reference to the underlying TcpStream.
    ///
    /// Example:
    /// ```no_run
    /// use tokio::net::TcpStream;
    /// use std::time::Duration;
    /// use async_ftp::FtpStream;
    ///
    /// async {
    ///   let stream = FtpStream::connect("172.25.82.139:21").await
    ///                          .expect("Couldn't connect to the server...");
    ///   let s: &TcpStream = stream.get_ref();
    /// };
    /// ```
    pub fn get_ref(&self) -> &TcpStream {
        self.reader.get_ref().get_ref()
    }

    /// Get welcome message from the server on connect.
    pub fn get_welcome_msg(&self) -> Option<&str> {
        self.welcome_msg.as_deref()
    }

    /// Log in to the FTP server.
    pub async fn login(&mut self, user: &str, password: &str) -> Result<()> {
        self.write_str(format!("USER {}\r\n", user)).await?;
        let Line(code, _) = self
            .read_response_in(&[status::LOGGED_IN, status::NEED_PASSWORD])
            .await?;
        if code == status::NEED_PASSWORD {
            self.write_str(format!("PASS {}\r\n", password)).await?;
            self.read_response(status::LOGGED_IN).await?;
        }
        Ok(())
    }

    /// Change the current directory to the path specified.
    pub async fn cwd(&mut self, path: &str) -> Result<()> {
        self.write_str(format!("CWD {}\r\n", path)).await?;
        self.read_response(status::REQUESTED_FILE_ACTION_OK).await?;
        Ok(())
    }

    /// Move the current directory to the parent directory.
    pub async fn cdup(&mut self) -> Result<()> {
        self.write_str("CDUP\r\n").await?;
        self.read_response_in(&[status::COMMAND_OK, status::REQUESTED_FILE_ACTION_OK])
            .await?;
        Ok(())
    }

    /// Gets the current directory
    pub async fn pwd(&mut self) -> Result<String> {
        self.write_str("PWD\r\n").await?;
        self.read_response(status::PATH_CREATED)
            .await
            .and_then(
                |Line(_, content)| match (content.find('"'), content.rfind('"')) {
                    (Some(begin), Some(end)) if begin < end => {
                        Ok(content[begin + 1..end].to_string())
                    }
                    _ => {
                        let cause = format!("Invalid PWD Response: {}", content);
                        Err(FtpError::InvalidResponse(cause))
                    }
                },
            )
    }

    /// This does nothing. This is usually just used to keep the connection open.
    pub async fn noop(&mut self) -> Result<()> {
        self.write_str("NOOP\r\n").await?;
        self.read_response(status::COMMAND_OK).await?;
        Ok(())
    }

    /// This creates a new directory on the server.
    pub async fn mkdir(&mut self, pathname: &str) -> Result<()> {
        self.write_str(format!("MKD {}\r\n", pathname)).await?;
        self.read_response(status::PATH_CREATED).await?;
        Ok(())
    }

    /// Runs the PASV command.
    async fn pasv(&mut self) -> Result<SocketAddr> {
        self.write_str("PASV\r\n").await?;
        // PASV response format : 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2).
        let Line(_, line) = self.read_response(status::PASSIVE_MODE).await?;
        PORT_RE
            .captures(&line)
            .ok_or_else(|| FtpError::InvalidResponse(format!("Invalid PASV response: {}", line)))
            .and_then(|caps| {
                // If the regex matches we can be sure groups contains numbers
                let (msb, lsb) = (
                    caps[5].parse::<u8>().unwrap(),
                    caps[6].parse::<u8>().unwrap(),
                );
                let port = ((msb as u16) << 8) + lsb as u16;

                let ip = self
                    .get_ref()
                    .peer_addr()
                    .map_err(FtpError::ConnectionError)?
                    .ip();
                Ok(SocketAddr::new(ip, port))
            })
    }

    /// Sets the type of file to be transferred. That is the implementation
    /// of `TYPE` command.
    pub async fn transfer_type(&mut self, file_type: FileType) -> Result<()> {
        let type_command = format!("TYPE {}\r\n", file_type.to_string());
        self.write_str(&type_command).await?;
        self.read_response(status::COMMAND_OK).await?;
        Ok(())
    }

    /// Quits the current FTP session.
    pub async fn quit(&mut self) -> Result<()> {
        self.write_str("QUIT\r\n").await?;
        self.read_response(status::CLOSING).await?;
        Ok(())
    }
    /// Sets the byte from which the transfer is to be restarted.
    pub async fn restart_from(&mut self, offset: u64) -> Result<()> {
        let rest_command = format!("REST {}\r\n", offset.to_string());
        self.write_str(&rest_command).await?;
        self.read_response(status::REQUEST_FILE_PENDING)
            .await
            .map(|_| ())
    }

    /// Retrieves the file name specified from the server.
    /// This method is a more complicated way to retrieve a file.
    /// The reader returned should be dropped.
    /// Also you will have to read the response to make sure it has the correct value.
    pub async fn get(&mut self, file_name: &str) -> Result<BufReader<DataStream>> {
        let retr_command = format!("RETR {}\r\n", file_name);
        let data_stream = BufReader::new(self.data_command(&retr_command).await?);
        self.read_response_in(&[status::ABOUT_TO_SEND, status::ALREADY_OPEN])
            .await?;
        Ok(data_stream)
    }

    /// Renames the file from_name to to_name
    pub async fn rename(&mut self, from_name: &str, to_name: &str) -> Result<()> {
        self.write_str(format!("RNFR {}\r\n", from_name)).await?;
        self.read_response(status::REQUEST_FILE_PENDING).await?;
        self.write_str(format!("RNTO {}\r\n", to_name)).await?;
        self.read_response(status::REQUESTED_FILE_ACTION_OK).await?;
        Ok(())
    }

    /// The implementation of `RETR` command where `filename` is the name of the file
    /// to download from FTP and `reader` is the function which operates with the
    /// data stream opened.
    ///
    /// ```
    /// use async_ftp::{FtpStream, DataStream, FtpError};
    /// use tokio::io::{AsyncReadExt, BufReader};
    /// use std::io::Cursor;
    /// async {
    ///   let mut conn = FtpStream::connect("172.25.82.139:21").await.unwrap();
    ///   conn.login("Doe", "mumble").await.unwrap();
    ///   let mut reader = Cursor::new("hello, world!".as_bytes());
    ///   conn.put("retr.txt", &mut reader).await.unwrap();
    ///
    ///   async fn lambda(mut reader: BufReader<DataStream>) -> Result<Vec<u8>, FtpError> {
    ///     let mut buffer = Vec::new();
    ///     reader
    ///         .read_to_end(&mut buffer)
    ///         .await
    ///         .map_err(FtpError::ConnectionError)?;
    ///     assert_eq!(buffer, "hello, world!".as_bytes());
    ///     Ok(buffer)
    ///   };
    ///
    ///   assert!(conn.retr("retr.txt", lambda).await.is_ok());
    ///   assert!(conn.rm("retr.txt").await.is_ok());
    /// };
    /// ```
    pub async fn retr<F, T, P, E>(&mut self, filename: &str, reader: F) -> std::result::Result<T, E>
    where
        F: Fn(BufReader<DataStream>) -> P,
        P: std::future::Future<Output = std::result::Result<T, E>>,
        E: From<FtpError>,
    {
        let retr_command = format!("RETR {}\r\n", filename);

        let data_stream = BufReader::new(self.data_command(&retr_command).await?);
        self.read_response_in(&[status::ABOUT_TO_SEND, status::ALREADY_OPEN])
            .await?;

        let res = reader(data_stream).await?;

        self.read_response_in(&[
            status::CLOSING_DATA_CONNECTION,
            status::REQUESTED_FILE_ACTION_OK,
        ])
        .await?;

        Ok(res)
    }

    /// Simple way to retr a file from the server. This stores the file in memory.
    ///
    /// ```
    /// use async_ftp::{FtpStream, FtpError};
    /// use std::io::Cursor;
    /// async {
    ///     let mut conn = FtpStream::connect("172.25.82.139:21").await?;
    ///     conn.login("Doe", "mumble").await?;
    ///     let mut reader = Cursor::new("hello, world!".as_bytes());
    ///     conn.put("simple_retr.txt", &mut reader).await?;
    ///
    ///     let cursor = conn.simple_retr("simple_retr.txt").await?;
    ///
    ///     assert_eq!(cursor.into_inner(), "hello, world!".as_bytes());
    ///     assert!(conn.rm("simple_retr.txt").await.is_ok());
    ///
    ///     Ok::<(), FtpError>(())
    /// };
    /// ```
    pub async fn simple_retr(&mut self, file_name: &str) -> Result<std::io::Cursor<Vec<u8>>> {
        async fn lambda(mut reader: BufReader<DataStream>) -> Result<Vec<u8>> {
            let mut buffer = Vec::new();
            reader
                .read_to_end(&mut buffer)
                .await
                .map_err(FtpError::ConnectionError)?;

            Ok(buffer)
        }

        let buffer = self.retr(file_name, lambda).await?;
        Ok(std::io::Cursor::new(buffer))
    }

    /// Removes the remote pathname from the server.
    pub async fn rmdir(&mut self, pathname: &str) -> Result<()> {
        self.write_str(format!("RMD {}\r\n", pathname)).await?;
        self.read_response(status::REQUESTED_FILE_ACTION_OK).await?;
        Ok(())
    }

    /// Remove the remote file from the server.
    pub async fn rm(&mut self, filename: &str) -> Result<()> {
        self.write_str(format!("DELE {}\r\n", filename)).await?;
        self.read_response(status::REQUESTED_FILE_ACTION_OK).await?;
        Ok(())
    }

    async fn put_file<R: AsyncRead + Unpin>(&mut self, filename: &str, r: &mut R) -> Result<()> {
        let stor_command = format!("STOR {}\r\n", filename);
        let mut data_stream = BufWriter::new(self.data_command(&stor_command).await?);
        self.read_response_in(&[status::ALREADY_OPEN, status::ABOUT_TO_SEND])
            .await?;
        copy(r, &mut data_stream)
            .await
            .map_err(FtpError::ConnectionError)?;
        Ok(())
    }

    /// This stores a file on the server.
    pub async fn put<R: AsyncRead + Unpin>(&mut self, filename: &str, r: &mut R) -> Result<()> {
        self.put_file(filename, r).await?;
        self.read_response_in(&[
            status::CLOSING_DATA_CONNECTION,
            status::REQUESTED_FILE_ACTION_OK,
        ])
        .await?;
        Ok(())
    }

    /// Execute a command which returns list of strings in a separate stream
    async fn list_command(
        &mut self,
        cmd: Cow<'_, str>,
        open_code: u32,
        close_code: &[u32],
    ) -> Result<Vec<String>> {
        let data_stream = BufReader::new(self.data_command(&cmd).await?);
        self.read_response_in(&[open_code, status::ALREADY_OPEN])
            .await?;
        let lines = Self::get_lines_from_stream(data_stream).await?;
        self.read_response_in(close_code).await?;
        Ok(lines)
    }

    /// Consume a stream and return a vector of lines
    async fn get_lines_from_stream<R>(data_stream: R) -> Result<Vec<String>>
    where
        R: AsyncBufRead + Unpin,
    {
        let mut lines: Vec<String> = Vec::new();

        let mut lines_stream = data_stream.lines();
        loop {
            let line = lines_stream
                .next_line()
                .await
                .map_err(FtpError::ConnectionError)?;

            match line {
                Some(line) => {
                    if line.is_empty() {
                        continue;
                    }
                    lines.push(line);
                }
                None => break Ok(lines),
            }
        }
    }

    /// Execute `LIST` command which returns the detailed file listing in human readable format.
    /// If `pathname` is omited then the list of files in the current directory will be
    /// returned otherwise it will the list of files on `pathname`.
    pub async fn list(&mut self, pathname: Option<&str>) -> Result<Vec<String>> {
        let command = pathname.map_or("LIST\r\n".into(), |path| {
            format!("LIST {}\r\n", path).into()
        });

        self.list_command(
            command,
            status::ABOUT_TO_SEND,
            &[
                status::CLOSING_DATA_CONNECTION,
                status::REQUESTED_FILE_ACTION_OK,
            ],
        )
        .await
    }

    /// Execute `NLST` command which returns the list of file names only.
    /// If `pathname` is omited then the list of files in the current directory will be
    /// returned otherwise it will the list of files on `pathname`.
    pub async fn nlst(&mut self, pathname: Option<&str>) -> Result<Vec<String>> {
        let command = pathname.map_or("NLST\r\n".into(), |path| {
            format!("NLST {}\r\n", path).into()
        });

        self.list_command(
            command,
            status::ABOUT_TO_SEND,
            &[
                status::CLOSING_DATA_CONNECTION,
                status::REQUESTED_FILE_ACTION_OK,
            ],
        )
        .await
    }

    /// Retrieves the modification time of the file at `pathname` if it exists.
    /// In case the file does not exist `None` is returned.
    pub async fn mdtm(&mut self, pathname: &str) -> Result<Option<DateTime<Utc>>> {
        self.write_str(format!("MDTM {}\r\n", pathname)).await?;
        let Line(_, content) = self.read_response(status::FILE).await?;

        match MDTM_RE.captures(&content) {
            Some(caps) => {
                let (year, month, day) = (
                    caps[1].parse::<i32>().unwrap(),
                    caps[2].parse::<u32>().unwrap(),
                    caps[3].parse::<u32>().unwrap(),
                );
                let (hour, minute, second) = (
                    caps[4].parse::<u32>().unwrap(),
                    caps[5].parse::<u32>().unwrap(),
                    caps[6].parse::<u32>().unwrap(),
                );
                Ok(Some(
                    Utc.ymd(year, month, day).and_hms(hour, minute, second),
                ))
            }
            None => Ok(None),
        }
    }

    /// Retrieves the size of the file in bytes at `pathname` if it exists.
    /// In case the file does not exist `None` is returned.
    pub async fn size(&mut self, pathname: &str) -> Result<Option<usize>> {
        self.write_str(format!("SIZE {}\r\n", pathname)).await?;
        let Line(_, content) = self.read_response(status::FILE).await?;

        match SIZE_RE.captures(&content) {
            Some(caps) => Ok(Some(caps[1].parse().unwrap())),
            None => Ok(None),
        }
    }

    async fn write_str<S: AsRef<str>>(&mut self, command: S) -> Result<()> {
        if cfg!(feature = "debug_print") {
            print!("CMD {}", command.as_ref());
        }

        let stream = self.reader.get_mut();
        stream
            .write_all(command.as_ref().as_bytes())
            .await
            .map_err(FtpError::ConnectionError)
    }

    pub async fn read_response(&mut self, expected_code: u32) -> Result<Line> {
        self.read_response_in(&[expected_code]).await
    }

    /// Retrieve single line response
    pub async fn read_response_in(&mut self, expected_code: &[u32]) -> Result<Line> {
        let mut line = String::new();
        self.reader
            .read_line(&mut line)
            .await
            .map_err(FtpError::ConnectionError)?;

        if cfg!(feature = "debug_print") {
            print!("FTP {}", line);
        }

        if line.len() < 5 {
            return Err(FtpError::InvalidResponse(
                "error: could not read reply code".to_owned(),
            ));
        }

        let code: u32 = line[0..3].parse().map_err(|err| {
            FtpError::InvalidResponse(format!("error: could not parse reply code: {}", err))
        })?;

        // multiple line reply
        // loop while the line does not begin with the code and a space
        let expected = format!("{} ", &line[0..3]);
        while line.len() < 5 || line[0..4] != expected {
            line.clear();
            if let Err(e) = self.reader.read_line(&mut line).await {
                return Err(FtpError::ConnectionError(e));
            }

            if cfg!(feature = "debug_print") {
                print!("FTP {}", line);
            }
        }

        if expected_code.iter().any(|ec| code == *ec) {
            Ok(Line(code, line))
        } else {
            Err(FtpError::InvalidResponse(format!(
                "Expected code {:?}, got response: {}",
                expected_code, line
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::FtpStream;
    use tokio_stream::once;
    use tokio_util::io::StreamReader;

    #[tokio::test]
    async fn list_command_dos_newlines() {
        let data_stream = StreamReader::new(once(Ok::<_, std::io::Error>(
            b"Hello\r\nWorld\r\n\r\nBe\r\nHappy\r\n" as &[u8],
        )));

        assert_eq!(
            FtpStream::get_lines_from_stream(data_stream).await.unwrap(),
            ["Hello", "World", "Be", "Happy"]
                .iter()
                .map(<&str>::to_string)
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn list_command_unix_newlines() {
        let data_stream = StreamReader::new(once(Ok::<_, std::io::Error>(
            b"Hello\nWorld\n\nBe\nHappy\n" as &[u8],
        )));

        assert_eq!(
            FtpStream::get_lines_from_stream(data_stream).await.unwrap(),
            ["Hello", "World", "Be", "Happy"]
                .iter()
                .map(<&str>::to_string)
                .collect::<Vec<_>>()
        );
    }
}
