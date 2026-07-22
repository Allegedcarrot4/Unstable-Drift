//! Output formatting for the CLI.

use std::io::Write;

use drift::Response;

pub fn write_response(
    resp: &Response,
    include_headers: bool,
    output_path: Option<&str>,
    dump_header_path: Option<&str>,
) -> std::io::Result<()> {
    if let Some(path) = dump_header_path {
        let mut f = std::fs::File::create(path)?;
        write_status_and_headers(&mut f, resp)?;
    }

    // Body destination.
    if let Some(path) = output_path {
        if include_headers {
            let mut f = std::fs::File::create(path)?;
            write_status_and_headers(&mut f, resp)?;
            f.write_all(resp.bytes())?;
        } else {
            std::fs::write(path, resp.bytes())?;
        }
    } else {
        let mut out = std::io::stdout().lock();
        if include_headers {
            write_status_and_headers(&mut out, resp)?;
        }
        out.write_all(resp.bytes())?;
    }
    Ok(())
}

fn write_status_and_headers<W: Write>(w: &mut W, resp: &Response) -> std::io::Result<()> {
    writeln!(w, "HTTP/1.1 {}", resp.status())?;
    for h in resp.headers() {
        writeln!(w, "{}: {}", h.name, h.value)?;
    }
    writeln!(w)?;
    Ok(())
}

pub fn write_head_only(resp: &Response) -> std::io::Result<()> {
    let mut out = std::io::stdout().lock();
    write_status_and_headers(&mut out, resp)
}
