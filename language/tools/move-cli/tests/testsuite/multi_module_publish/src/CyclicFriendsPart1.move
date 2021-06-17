module 0x3::A {
    public fun foo() {}
}

module 0x3::B {
    public fun foo() { 0x3::A::foo() }
}
