use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::error::ProxyClientError;

pub(crate) fn parse_connect_target(target: &str) -> (String, u16) {
    if let Some((host, port_s)) = target.rsplit_once(':')
        && let Ok(port) = port_s.parse()
    {
        return (host.to_string(), port);
    }
    (target.to_string(), 443)
}

pub(crate) async fn read_connect_request(
    stream: &mut TcpStream,
) -> Result<(String, u16), ProxyClientError> {
    let request_line = read_line(stream).await?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        write_http_response(stream, "400 Bad Request", "").await?;
        return Err(ProxyClientError::Closed);
    }
    if parts[0].eq_ignore_ascii_case("CONNECT") {
        skip_http_headers(stream).await?;
        return Ok(parse_connect_target(parts[1]));
    }
    write_http_response(stream, "405 Method Not Allowed", "").await?;
    Err(ProxyClientError::Closed)
}

pub(crate) async fn read_line(stream: &mut TcpStream) -> Result<String, ProxyClientError> {
    let mut line = String::new();
    let mut byte = [0_u8; 1];
    loop {
        if stream.read_exact(&mut byte).await.is_err() {
            return Err(ProxyClientError::Closed);
        }
        line.push(byte[0] as char);
        if line.ends_with('\n') {
            break;
        }
    }
    Ok(line)
}

async fn skip_http_headers(stream: &mut TcpStream) -> Result<(), ProxyClientError> {
    loop {
        let line = read_line(stream).await?;
        if line == "\r\n" || line == "\n" {
            break;
        }
    }
    Ok(())
}

pub(crate) async fn write_http_response(
    stream: &mut TcpStream,
    status: &str,
    body: &str,
) -> Result<(), ProxyClientError> {
    use tokio::io::AsyncWriteExt;
    let msg = format!("HTTP/1.1 {status}\r\nContent-Type: text/plain\r\n\r\n{body}");
    stream.write_all(msg.as_bytes()).await?;
    Ok(())
}
