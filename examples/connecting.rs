use async_ftp::{FtpError, FtpStream};
use std::io::Cursor;
use std::str;

async fn test_ftp(addr: &str, user: &str, pass: &str) -> Result<(), FtpError> {
    let mut ftp_stream = FtpStream::connect((addr, 21)).await?;
    ftp_stream.login(user, pass).await?;
    println!("current dir: {}", ftp_stream.pwd().await?);

    ftp_stream.cwd("test_data").await?;

    // An easy way to retrieve a file
    let cursor = ftp_stream.simple_retr("ftpext-charter.txt").await?;
    let vec = cursor.into_inner();
    let text = str::from_utf8(&vec).unwrap();
    println!("got data: {}", text);

    // Store a file
    let file_data = format!("Some awesome file data man!!");
    let mut reader = Cursor::new(file_data.into_bytes());
    ftp_stream.put("my_random_file.txt", &mut reader).await?;

    ftp_stream.quit().await
}

fn main() {
    let future = test_ftp("172.25.82.139", "anonymous", "rust-ftp@github.com");

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
        .unwrap();

    println!("test successful")
}
