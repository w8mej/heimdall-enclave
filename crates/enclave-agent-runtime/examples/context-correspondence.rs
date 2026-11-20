//! Emit actual ContextDag decisions for bounded compiled-model comparison.
mod context_correspondence_support;

fn main() {
    for row in context_correspondence_support::decisions() {
        println!("{row}");
    }
}
