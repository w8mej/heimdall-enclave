//! Emit actual production Cedar decisions for comparison with compiled Lean.
mod authorization_correspondence_support;

fn main() {
    for row in authorization_correspondence_support::decisions() {
        println!("{row}");
    }
}
