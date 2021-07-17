module 0x3::A {
    public fun foo() {}
    public fun bar() {}
}

module 0x3::C {
    friend 0x3::A;
    public fun foo() { 0x3::B::foo() }
}
