use qrencode::types::Color;
use qrencode::QrCode;

pub(crate) fn qrcode_to_string(qrcode: QrCode) -> String {
    let mut colors = qrcode.to_colors();
    let n = (colors.len() as f64).sqrt() as usize;
    let nrows = if n % 2 == 1 {
        for _ in 0..n {
            colors.push(Color::Dark);
        }
        n + 1
    } else {
        n
    };
    let mut buf = String::with_capacity(
        (n + 2 * HORIZONTAL_PADDING.len() + 1) * (nrows + 2 * VERTICAL_PADDING_LINES),
    );
    vertical_padding(&mut buf, n);
    for i in (1..nrows).step_by(2) {
        buf.push_str(HORIZONTAL_PADDING);
        for j in 0..n {
            let ch = match (colors[(i - 1) * n + j], colors[i * n + j]) {
                (Color::Dark, Color::Dark) => '█',
                (Color::Light, Color::Dark) => '▄',
                (Color::Dark, Color::Light) => '▀',
                (Color::Light, Color::Light) => ' ',
            };
            buf.push(ch);
        }
        buf.push_str(HORIZONTAL_PADDING);
        buf.push('\n');
    }
    vertical_padding(&mut buf, n);
    buf
}

fn vertical_padding(buf: &mut String, n: usize) {
    for _ in 0..VERTICAL_PADDING_LINES {
        buf.push_str(HORIZONTAL_PADDING);
        for _ in 0..n {
            buf.push('█');
        }
        buf.push_str(HORIZONTAL_PADDING);
        buf.push('\n');
    }
}

const HORIZONTAL_PADDING: &str = "███";
const VERTICAL_PADDING_LINES: usize = 2;
