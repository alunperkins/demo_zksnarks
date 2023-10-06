use polynomen::Poly;
use std::fmt::Debug;

pub(crate) fn printpoly<T: Debug>(polynomial: &Poly<T>) {
    println!("{:?}", polynomial);
}
