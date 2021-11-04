use async_ftp::{FtpError, FtpStream};
#[cfg(test)]
use std::io::Cursor;

#[test]
fn test_ftp() {
    let future = async {
        let mut ftp_stream = FtpStream::connect("192.168.1.60:21").await?;
        let _ = ftp_stream.login("Doe", "mumble").await?;

        ftp_stream.mkdir("test_dir").await?;
        ftp_stream.cwd("test_dir").await?;
        assert!(ftp_stream.pwd().await?.ends_with("/test_dir"));

        // store a file
        let file_data = "test data\n";
        let mut reader = Cursor::new(file_data.as_bytes());
        ftp_stream.put("test_file.txt", &mut reader).await?;

        // retrieve file
        ftp_stream
            .simple_retr("test_file.txt")
            .await
            .map(|bytes| assert_eq!(bytes.into_inner(), file_data.as_bytes()))?;

        // remove file
        ftp_stream.rm("test_file.txt").await?;

        // cleanup: go up, remove folder, and quit
        ftp_stream.cdup().await?;

        ftp_stream.rmdir("test_dir").await?;
        ftp_stream.quit().await?;

        Ok(())
    };

    let result: Result<(), FtpError> = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future);

    result.unwrap();
}
