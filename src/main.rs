#![feature(proc_macro_hygiene, decl_macro, async_closure)]
extern crate gotham;
#[macro_use]
extern crate gotham_derive;
extern crate hyper;
#[macro_use]
extern crate lazy_static;
extern crate mime;

use jemallocator;

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;


mod state;
mod router;

/// Request counting struct, used to track the number of requests made.
///
/// Due to being shared across many worker threads, the internal counter
/// is bound inside an `Arc` (to enable sharing) and a `Mutex` (to enable
/// modification from multiple threads safely).
///
/// This struct must implement `Clone` and `StateData` to be applicable
/// for use with the `StateMiddleware`, and be shared via `Middleware`.


/// Basic `Handler` to say hello and return the current request count.
///
/// The request counter is shared via the state, so we can safely
/// borrow one from the provided state. As the counter uses locks
/// internally, we don't have to borrow a mutable reference either!


/// Constructs a simple router on `/` to say hello, along with
/// the current request count.


/// Start a server and call the `Handler` we've defined above
/// for each `Request` we receive.
pub fn main() {
    let addr = "127.0.0.1:7878";
    println!("Listening for requests at http://{}", addr);
    gotham::start(addr, router::ignite())
}