use async_ftp::{FtpError, FtpStream};
#[cfg(test)]
use std::io::Cursor;

#[test]
fn test_ftp() {
    let future = async {
        let mut ftp_stream = FtpStream::connect("172.25.82.139:21").await?;
        let _ = ftp_stream.login("Doe", "mumble").await?;

        ftp_stream.mkdir("test_dir").await?;
        ftp_stream.cwd("test_dir").await?;
        assert!(ftp_stream.pwd().await?.ends_with("/test_dir"));

        // store a file
        let file_data = "test data\n";
        let mut reader = Cursor::new(file_data.as_bytes());
        assert!(ftp_stream.put("test_file.txt", &mut reader).await.is_ok());

        // retrieve file
        assert!(ftp_stream
            .simple_retr("test_file.txt")
            .await
            .map(|bytes| assert_eq!(bytes.into_inner(), file_data.as_bytes()))
            .is_ok());

        // remove file
        assert!(ftp_stream.rm("test_file.txt").await.is_ok());

        // cleanup: go up, remove folder, and quit
        assert!(ftp_stream.cdup().await.is_ok());

        assert!(ftp_stream.rmdir("test_dir").await.is_ok());
        assert!(ftp_stream.quit().await.is_ok());

        Ok(())
    };

    let result: Result<(), FtpError> = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future);

    assert!(result.is_ok());
}
