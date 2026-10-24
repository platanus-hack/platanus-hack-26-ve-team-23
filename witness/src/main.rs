// Hide the Windows console in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    witness_lib::run();
}
