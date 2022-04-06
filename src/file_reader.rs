use std::{
    future::Future,
    io, mem,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, ReadBuf};

use crate::{status, DataStream, FtpStream};

pub struct FileReader<'a> {
    state: State<'a>,
}

enum State<'a> {
    Stream {
        data_stream: DataStream,
        ftp_stream: &'a mut FtpStream,
    },
    FinalRead(Pin<Box<dyn 'a + Future<Output = io::Result<()>>>>),
    Finished,
}

impl FileReader<'_> {
    pub(crate) fn new(data_stream: DataStream, ftp_stream: &mut FtpStream) -> FileReader {
        FileReader {
            state: State::Stream {
                data_stream,
                ftp_stream,
            },
        }
    }
}

impl AsyncRead for FileReader<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let bytes_read_before = buf.filled().len();
        let (state, result) = match mem::replace(&mut self.state, State::Finished) {
            State::Stream {
                mut data_stream,
                ftp_stream,
            } => match Pin::new(&mut data_stream).poll_read(cx, buf) {
                Poll::Ready(result) => {
                    let bytes_read_after = buf.filled().len();
                    if bytes_read_after == bytes_read_before {
                        // finished reading the file, wait for a status message from the server
                        let mut status_fut = Box::pin(async move {
                            ftp_stream
                                .read_response_in(&[
                                    status::CLOSING_DATA_CONNECTION,
                                    status::REQUESTED_FILE_ACTION_OK,
                                ])
                                .await
                                .map(|_| ())
                                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
                                .and(result)
                        });
                        match Pin::new(&mut status_fut).poll(cx) {
                            Poll::Ready(r) => (State::Finished, Poll::Ready(r)),
                            Poll::Pending => (State::FinalRead(status_fut), Poll::Pending),
                        }
                    } else {
                        (
                            State::Stream {
                                data_stream,
                                ftp_stream,
                            },
                            Poll::Ready(result),
                        )
                    }
                }
                Poll::Pending => (
                    State::Stream {
                        data_stream,
                        ftp_stream,
                    },
                    Poll::Pending,
                ),
            },
            State::FinalRead(mut status_fut) => match Pin::new(&mut status_fut).poll(cx) {
                Poll::Ready(r) => (State::Finished, Poll::Ready(r)),
                Poll::Pending => (State::FinalRead(status_fut), Poll::Pending),
            },
            State::Finished => panic!("poll called on finished FileReader"),
        };

        self.state = state;
        result
    }
}
