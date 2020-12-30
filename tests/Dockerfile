FROM ubuntu:latest

RUN apt update && apt install -y vsftpd

RUN useradd --home-dir /home/ftp --create-home --groups ftp Doe
RUN echo "Doe:mumble" | chpasswd

RUN cp /etc/vsftpd.conf /etc/vsftpd.conf.orig
RUN echo "write_enable=yes\nlog_ftp_protocol=yes" > /etc/vsftpd.conf
RUN cat /etc/vsftpd.conf.orig >> /etc/vsftpd.conf
    
RUN echo "/etc/init.d/vsftpd start" | tee -a /etc/bash.bashrc

CMD ["/bin/bash"]
