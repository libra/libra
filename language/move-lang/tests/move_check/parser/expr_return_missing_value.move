module 0x8675309::M {
    fun f(v: u64) {
        // Check a return without the optional return value
        if (v > 100) return
    }
}
