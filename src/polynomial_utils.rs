// I realise there are libraries for these things, but I'm here to learn so I'm doing it myself

use std::fmt::Debug;

use polynomen::Poly;
// use polynomials::Polynomial;

pub fn printpoly<T: Debug>(polynomial: &Poly<T>) {
    println!("{:?}", polynomial);
}
