use std::fmt::{Formatter, LowerHex};

pub struct Hex<'a>(pub &'a [u8]);

impl LowerHex for Hex<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for &it in self.0 {
            write!(f, "{:02x}", it)?;
        }
        Ok(())
    }
}
