mod session;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    std::process::exit(session::qobject::run_app(args));
}
