use std::io::Write;

use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

pub(crate) fn print_color(text: &str, color: Color) {
    let mut stdout = StandardStream::stdout(ColorChoice::Always);
    stdout
        .set_color(ColorSpec::new().set_fg(Some(color)))
        .expect("error setting term color");
    write!(&mut stdout, "{}", text).expect("error writing to console");
    stdout.reset().expect("error setting term color");
}
