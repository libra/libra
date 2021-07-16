/// Allows transactions to be executed out-of-order while ensuring that they are executed at most once.
/// Nonces are assigned to transactions off-chain by clients submitting the transactions.
/// It maintains a sliding window bitvector of 128 flags.  A flag of 0 indicates that the transaction
/// with that nonce has not yet been executed.
/// When nonce X is recorded, all transactions with nonces lower then X-128 will abort.
module DiemFramework::SlidingNonce {
    use Std::Signer;
    use Std::Errors;
    friend DiemFramework::DiemAccount;

    struct SlidingNonce has key {
        /// Minimum nonce in sliding window. All transactions with smaller
        /// nonces will be automatically rejected, since the window cannot
        /// tell whether they have been executed or not.
        min_nonce: u64,
        /// Bit-vector of window of nonce values
        nonce_mask: u128,
    }

    /// The `SlidingNonce` resource is in an invalid state
    const ESLIDING_NONCE: u64 = 0;
    /// The nonce aborted because it's too old (nonce smaller than `min_nonce`)
    const ENONCE_TOO_OLD: u64 = 1;
    /// The nonce is too large - this protects against nonce exhaustion
    const ENONCE_TOO_NEW: u64 = 2;
    /// The nonce was already recorded previously
    const ENONCE_ALREADY_RECORDED: u64 = 3;
    /// The sliding nonce resource was already published
    const ENONCE_ALREADY_PUBLISHED: u64 = 4;

    /// Size of SlidingNonce::nonce_mask in bits.
    const NONCE_MASK_SIZE: u64 = 128;

    /// Calls `try_record_nonce` and aborts transaction if returned code is non-0
    public fun record_nonce_or_abort(account: &signer, seq_nonce: u64) acquires SlidingNonce {
        let code = try_record_nonce(account, seq_nonce);
        assert(code == 0, Errors::invalid_argument(code));
    }

    spec record_nonce_or_abort {
        include RecordNonceAbortsIf;
    }

    spec schema RecordNonceAbortsIf {
        account: signer;
        seq_nonce: u64;
        aborts_if !exists<SlidingNonce>(Signer::spec_address_of(account)) with Errors::NOT_PUBLISHED;
        aborts_if spec_try_record_nonce(account, seq_nonce) != 0 with Errors::INVALID_ARGUMENT;
    }

    /// # Explanation of the Algorithm
    ///
    /// We have an "infinite" bitvector. The `min_nonce` tells us the starting
    /// index of the window. The window size is the size of the bitmask we can
    /// represent in a 128-bit wide bitmap. The `seq_nonce` that is sent represents
    /// setting a bit at index `seq_nonce` in this infinite bitvector. Because of
    /// this, if the same `seq_nonce` is passed in multiple times, that bit will be
    /// set, and we can signal an error. In order to represent
    /// the `seq_nonce` the window we are looking at must be shifted so that
    /// `seq_nonce` lies within that 128-bit window and, since the `min_nonce`
    /// represents the left-hand-side of this window, it must be increased to be no
    /// less than `seq_nonce - 128`.
    ///
    /// The process of shifting window will invalidate other transactions that
    /// have a `seq_nonce` number that are to the "left" of this window (i.e., less
    /// than `min_nonce`) since it cannot be represented in the current window, and the
    /// window can only move forward and never backwards.
    ///
    /// In order to prevent shifting this window over too much at any one time, a
    /// `jump_limit` is imposed. If a `seq_nonce` is provided that would cause the
    /// `min_nonce` to need to be increased by more than the `jump_limit` this will
    /// cause a failure.
    ///
    /// # Some Examples
    ///
    /// Let's say we start out with a clean `SlidingNonce` published under `account`,
    /// this will look like this:
    /// ```
    /// 000000000000000000...00000000000000000000000000000...
    /// ^             ...                ^
    /// |_____________...________________|
    /// min_nonce = 0             min_nonce + NONCE_MASK_SIZE = 0 + 64 = 64
    /// ```
    ///
    /// # Example 1:
    ///
    /// Let's see what happens when we call`SlidingNonce::try_record_nonce(account, 8)`:
    ///
    /// 1. Determine the bit position w.r.t. the current window:
    ///     ```
    ///     bit_pos = 8 - min_nonce ~~~ 8 - 0 = 8
    ///     ```
    /// 2. See if the bit position that was calculated is not within the current window:
    ///     ```
    ///     bit_pos >= NONCE_MASK_SIZE ~~~ 8 >= 128 = FALSE
    ///     ```
    /// 3. `bit_pos` is in window, so set the 8'th bit in the window:
    /// ```
    /// 000000010000000000...00000000000000000000000000000...
    /// ^             ...                ^
    /// |_____________...________________|
    /// min_nonce = 0             min_nonce + NONCE_MASK_SIZE = 0 + 64 = 64
    /// ```
    ///
    /// # Example 2:
    ///
    /// Let's see what happens when we call `SlidingNonce::try_record_nonce(account, 129)`:
    ///
    /// 1. Figure out the bit position w.r.t. the current window:
    ///     ```
    ///     bit_pos = 129 - min_nonce ~~~ 129 - 0 = 129
    ///     ```
    /// 2. See if bit position calculated is not within the current window starting at `min_nonce`:
    ///     ```
    ///     bit_pos >= NONCE_MASK_SIZE ~~~ 129 >= 128 = TRUE
    ///     ```
    /// 3. `bit_pos` is outside of the current window. So we need to shift the window over. Now calculate the amount that
    ///    the window needs to be shifted over (i.e., the amount that `min_nonce` needs to be increased by) so that
    ///    `seq_nonce` lies within the `NONCE_MASK_SIZE` window starting at `min_nonce`.
    /// 3a. Calculate the amount that the window needs to be shifted for `bit_pos` to lie within it:
    ///     ```
    ///     shift = bit_pos - NONCE_MASK_SIZE + 1 ~~~ 129 - 128 + 1 = 2
    ///     ```
    /// 3b. See if there is no overlap between the new window that we need to shift to and the old window:
    ///     ```
    ///     shift >= NONCE_MASK_SIZE ~~~ 2 >= 128 = FALSE
    ///     ```
    /// 3c. Since there is an overlap between the new window that we need to shift to and the previous
    ///     window, shift the window over, but keep the current set bits in the overlapping part of the window:
    ///     ```
    ///     nonce_mask = nonce_mask >> shift; min_nonce += shift;
    ///     ```
    /// 4. Now that the window has been shifted over so that the `seq_nonce` index lies within the new window we
    ///    recompute the `bit_pos` w.r.t. to it (recall `min_nonce` was updated):
    ///     ```
    ///     bit_pos = seq - min_nonce ~~~ 129 - 2 = 127
    ///     ```
    /// 5. We set the bit_pos position bit within the new window:
    /// ```
    /// 00000001000000000000000...000000000000000000000000000000000000000000010...
    ///        ^               ...                                           ^^
    ///        |               ...                                           ||
    ///        |               ...                                 new_set_bit|
    ///        |_______________...____________________________________________|
    ///      min_nonce = 2                            min_nonce + NONCE_MASK_SIZE = 2 + 128 = 130
    ///  ```
    ///
    /// # Example 3:
    ///
    /// Let's see what happens when we call `SlidingNonce::try_record_nonce(account, 400)`:
    ///
    /// 1. Figure out the bit position w.r.t. the current window:
    ///     ```
    ///     bit_pos = 400 - min_nonce ~~~ 400 - 2 = 398
    ///     ```
    /// 2. See if bit position calculated is not within the current window:
    ///     ```
    ///     bit_pos >= NONCE_MASK_SIZE ~~~ 398 >= 128 = TRUE
    ///     ```
    /// 3. `bit_pos` is out of the window. Now calculate the amount that
    ///    the window needs to be shifted over (i.e., that `min_nonce` needs to be incremented) so
    ///    `seq_nonce` lies within the `NONCE_MASK_SIZE` window starting at min_nonce.
    /// 3a. Calculate the amount that the window needs to be shifted for `bit_pos` to lie within it:
    ///     ```
    ///     shift = bit_pos - NONCE_MASK_SIZE + 1 ~~~ 398 - 128 + 1 = 271
    ///     ```
    /// 3b. See if there is no overlap between the new window that we need to shift to and the old window:
    ///     ```
    ///     shift >= NONCE_MASK_SIZE ~~~ 271 >= 128 = TRUE
    ///     ```
    /// 3c. Since there is no overlap between the new window that we need to shift to and the previous
    ///     window we zero out the bitmap, and update the `min_nonce` to start at the out-of-range `seq_nonce`:
    ///     ```
    ///     nonce_mask = 0; min_nonce = seq_nonce + 1 - NONCE_MASK_SIZE = 273;
    ///     ```
    /// 4. Now that the window has been shifted over so that the `seq_nonce` index lies within the window we
    ///    recompute the bit_pos:
    ///     ```
    ///     bit_pos = seq_nonce - min_nonce ~~~ 400 - 273 = 127
    ///     ```
    /// 5. We set the bit_pos position bit within the new window:
    /// ```
    /// ...00000001000000000000000...000000000000000000000000000000000000000000010...
    ///           ^               ...                                           ^^
    ///           |               ...                                           ||
    ///           |               ...                                 new_set_bit|
    ///           |_______________...____________________________________________|
    ///         min_nonce = 273                          min_nonce + NONCE_MASK_SIZE = 273 + 128 = 401
    /// ```
    /// Tries to record this nonce in the account.
    /// Returns 0 if a nonce was recorded and non-0 otherwise
    public fun try_record_nonce(account: &signer, seq_nonce: u64): u64 acquires SlidingNonce {
        if (seq_nonce == 0) {
            return 0
        };
        assert(exists<SlidingNonce>(Signer::address_of(account)), Errors::not_published(ESLIDING_NONCE));
        let t = borrow_global_mut<SlidingNonce>(Signer::address_of(account));
        // The `seq_nonce` is outside the current window to the "left" and is
        // no longer valid since we can't shift the window back.
        if (t.min_nonce > seq_nonce) {
            return ENONCE_TOO_OLD
        };
        // Don't allow giant leaps in nonce to protect against nonce exhaustion
        // If we try to move a window by more than this amount, we will fail.
        let jump_limit = 10000;
        if (t.min_nonce + jump_limit <= seq_nonce) {
            return ENONCE_TOO_NEW
        };
        // Calculate The bit position in the window that will be set in our window
        let bit_pos = seq_nonce - t.min_nonce;

        // See if the bit position that we want to set lies outside the current
        // window that we have under the current `min_nonce`.
        if (bit_pos >= NONCE_MASK_SIZE) {
            // Determine how much we need to shift the current window over (to
            // the "right") so that `bit_pos` lies within the new window.
            let shift = (bit_pos - NONCE_MASK_SIZE + 1);

            // If we are shifting the window over by more than one window's width
            // reset the bits in the window, and update the
            // new start of the `min_nonce` so that `seq_nonce` is the
            // right-most bit in the new window.
            if(shift >= NONCE_MASK_SIZE) {
                t.nonce_mask = 0;
                t.min_nonce = seq_nonce + 1 - NONCE_MASK_SIZE;
            } else {
                // We are shifting the window over by less than a windows width,
                // so we need to keep the current set bits in the window
                t.nonce_mask = t.nonce_mask >> (shift as u8);
                t.min_nonce = t.min_nonce + shift;
            }
        };
        // The window has been (possibly) shifted over so that `seq_nonce` lies
        // within the window. Recompute the bit positition that needs to be set
        // within the (possibly) new window.
        let bit_pos = seq_nonce - t.min_nonce;
        let set = 1u128 << (bit_pos as u8);
        // The bit was already set, so return an error.
        if (t.nonce_mask & set != 0) {
            return ENONCE_ALREADY_RECORDED
        };
        t.nonce_mask = t.nonce_mask | set;
        0
    }

    spec try_record_nonce {
        /// It is currently assumed that this function raises no arithmetic overflow/underflow.
        /// >Note: Verification is turned off. For verifying callers, this is effectively abstracted into a function
        /// that returns arbitrary results because `spec_try_record_nonce` is uninterpreted.
        pragma opaque, verify = false;
        ensures result == spec_try_record_nonce(account, seq_nonce);
        aborts_if !exists<SlidingNonce>(Signer::spec_address_of(account)) with Errors::NOT_PUBLISHED;
        modifies global<SlidingNonce>(Signer::spec_address_of(account));
    }

    /// Specification version of `Self::try_record_nonce`.
    spec fun spec_try_record_nonce(account: signer, seq_nonce: u64): u64;

    /// Publishes nonce resource for `account`
    /// This is required before other functions in this module can be called for `account`
    public(friend) fun publish(account: &signer) {
        assert(!exists<SlidingNonce>(Signer::address_of(account)), Errors::already_published(ENONCE_ALREADY_PUBLISHED));
        move_to(account, SlidingNonce {  min_nonce: 0, nonce_mask: 0 });
    }
    spec publish {
        pragma opaque;
        modifies global<SlidingNonce>(Signer::spec_address_of(account));
        aborts_if exists<SlidingNonce>(Signer::spec_address_of(account)) with Errors::ALREADY_PUBLISHED;
        ensures exists<SlidingNonce>(Signer::spec_address_of(account));
    }

    // =================================================================
    // Module Specification

    spec module {} // Switch to module documentation context

    spec module {
        use DiemFramework::DiemTimestamp;

        /// Sliding nonces are initialized at Diem root and treasury compliance addresses
        invariant DiemTimestamp::is_operating()
            ==> exists<SlidingNonce>(@DiemRoot);

        invariant DiemTimestamp::is_operating()
            ==> exists<SlidingNonce>(@TreasuryCompliance);

        // In the current code, only Diem root and Treasury compliance have sliding nonces.
        // That is a difficult cross-module invariant to prove (it depends on Genesis and
        // DiemAccount). Additional modules could be added that call the publish functions
        // in this module to publish sliding nonces on other accounts.  Anyway, this property
        // is probably not very important.
    }
}
