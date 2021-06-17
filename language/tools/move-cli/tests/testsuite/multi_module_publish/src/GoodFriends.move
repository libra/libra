module 0x2::A {
    friend 0x2::B;
    public(friend) fun foo() {}
}

module 0x2::B {
    fun bar() { 0x2::A::foo() }
}
