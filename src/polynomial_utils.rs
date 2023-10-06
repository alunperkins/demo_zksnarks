use polynomen::Poly;
use std::fmt::Debug;

pub fn printpoly<T: Debug>(polynomial: &Poly<T>) {
    println!("{:?}", polynomial);
}
