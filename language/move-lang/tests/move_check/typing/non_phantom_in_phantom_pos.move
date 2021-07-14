module 0x42::M {
    struct S1<phantom T1, T2> { f: T2 }

    // T1 is only being used in phantom position
    struct S2<T1, T2> {
        a: S1<T1, T2>
    }

    // This is ok, because T is used both in phantom and non-phantom position.
    struct S3<T> {
        a: S1<T, T>
    }

    // Invalid position inside another type
    struct S4<T1, T2> {
        a: S2<S1<T1, T2>, T2>
    }
}
