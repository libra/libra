
<a name="0x1_XUS"></a>

# Module `0x1::XUS`

This module defines the coin type XUS and its initialization function.


-  [Struct `XUS`](#0x1_XUS_XUS)
-  [Function `initialize`](#0x1_XUS_initialize)
-  [Module Specification](#@Module_Specification_0)
    -  [Persistence of Resources](#@Persistence_of_Resources_1)


<pre><code><b>use</b> <a href="AccountLimits.md#0x1_AccountLimits">0x1::AccountLimits</a>;
<b>use</b> <a href="Diem.md#0x1_Diem">0x1::Diem</a>;
<b>use</b> <a href="DiemTimestamp.md#0x1_DiemTimestamp">0x1::DiemTimestamp</a>;
<b>use</b> <a href="../../../../../../move-stdlib/docs/FixedPoint32.md#0x1_FixedPoint32">0x1::FixedPoint32</a>;
<b>use</b> <a href="Roles.md#0x1_Roles">0x1::Roles</a>;
</code></pre>



<a name="0x1_XUS_XUS"></a>

## Struct `XUS`

The type tag representing the <code><a href="XUS.md#0x1_XUS">XUS</a></code> currency on-chain.


<pre><code><b>struct</b> <a href="XUS.md#0x1_XUS">XUS</a>
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>dummy_field: bool</code>
</dt>
<dd>

</dd>
</dl>


</details>

<a name="0x1_XUS_initialize"></a>

## Function `initialize`

Registers the <code><a href="XUS.md#0x1_XUS">XUS</a></code> cointype. This can only be called from genesis.


<pre><code><b>public</b> <b>fun</b> <a href="XUS.md#0x1_XUS_initialize">initialize</a>(dr_account: &signer, tc_account: &signer)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="XUS.md#0x1_XUS_initialize">initialize</a>(
    dr_account: &signer,
    tc_account: &signer,
) {
    <a href="DiemTimestamp.md#0x1_DiemTimestamp_assert_genesis">DiemTimestamp::assert_genesis</a>();
    <a href="Roles.md#0x1_Roles_assert_treasury_compliance">Roles::assert_treasury_compliance</a>(tc_account);
    <a href="Roles.md#0x1_Roles_assert_diem_root">Roles::assert_diem_root</a>(dr_account);
    <a href="Diem.md#0x1_Diem_register_SCS_currency">Diem::register_SCS_currency</a>&lt;<a href="XUS.md#0x1_XUS">XUS</a>&gt;(
        dr_account,
        tc_account,
        <a href="../../../../../../move-stdlib/docs/FixedPoint32.md#0x1_FixedPoint32_create_from_rational">FixedPoint32::create_from_rational</a>(1, 1), // exchange rate <b>to</b> <a href="XDX.md#0x1_XDX">XDX</a>
        1000000, // scaling_factor = 10^6
        100,     // fractional_part = 10^2
        b"<a href="XUS.md#0x1_XUS">XUS</a>"
    );
    <a href="AccountLimits.md#0x1_AccountLimits_publish_unrestricted_limits">AccountLimits::publish_unrestricted_limits</a>&lt;<a href="XUS.md#0x1_XUS">XUS</a>&gt;(dr_account);
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="Diem.md#0x1_Diem_RegisterSCSCurrencyAbortsIf">Diem::RegisterSCSCurrencyAbortsIf</a>&lt;<a href="XUS.md#0x1_XUS">XUS</a>&gt;{
    currency_code: b"<a href="XUS.md#0x1_XUS">XUS</a>",
    scaling_factor: 1000000
};
<b>include</b> <a href="AccountLimits.md#0x1_AccountLimits_PublishUnrestrictedLimitsAbortsIf">AccountLimits::PublishUnrestrictedLimitsAbortsIf</a>&lt;<a href="XUS.md#0x1_XUS">XUS</a>&gt;{publish_account: dr_account};
<b>include</b> <a href="Diem.md#0x1_Diem_RegisterSCSCurrencyEnsures">Diem::RegisterSCSCurrencyEnsures</a>&lt;<a href="XUS.md#0x1_XUS">XUS</a>&gt;;
<b>include</b> <a href="AccountLimits.md#0x1_AccountLimits_PublishUnrestrictedLimitsEnsures">AccountLimits::PublishUnrestrictedLimitsEnsures</a>&lt;<a href="XUS.md#0x1_XUS">XUS</a>&gt;{publish_account: dr_account};
</code></pre>


Registering XUS can only be done in genesis.


<pre><code><b>include</b> <a href="DiemTimestamp.md#0x1_DiemTimestamp_AbortsIfNotGenesis">DiemTimestamp::AbortsIfNotGenesis</a>;
</code></pre>


Only the DiemRoot account can register a new currency [[H8]][PERMISSION].


<pre><code><b>include</b> <a href="Roles.md#0x1_Roles_AbortsIfNotDiemRoot">Roles::AbortsIfNotDiemRoot</a>{account: dr_account};
</code></pre>


Only a TreasuryCompliance account can have the MintCapability [[H1]][PERMISSION].
Moreover, only a TreasuryCompliance account can have the BurnCapability [[H3]][PERMISSION].


<pre><code><b>include</b> <a href="Roles.md#0x1_Roles_AbortsIfNotTreasuryCompliance">Roles::AbortsIfNotTreasuryCompliance</a>{account: tc_account};
</code></pre>



</details>

<a name="@Module_Specification_0"></a>

## Module Specification



<a name="@Persistence_of_Resources_1"></a>

### Persistence of Resources


After genesis, XUS is registered.


<pre><code><b>invariant</b> <a href="DiemTimestamp.md#0x1_DiemTimestamp_is_operating">DiemTimestamp::is_operating</a>() ==&gt; <a href="Diem.md#0x1_Diem_is_currency">Diem::is_currency</a>&lt;<a href="XUS.md#0x1_XUS">XUS</a>&gt;();
</code></pre>


After genesis, <code>LimitsDefinition&lt;<a href="XUS.md#0x1_XUS">XUS</a>&gt;</code> is published at Diem root. It's published by
AccountLimits::publish_unrestricted_limits, but we can't prove the condition there because
it does not hold for all types (but does hold for XUS).


<pre><code><b>invariant</b> <a href="DiemTimestamp.md#0x1_DiemTimestamp_is_operating">DiemTimestamp::is_operating</a>()
    ==&gt; <b>exists</b>&lt;<a href="AccountLimits.md#0x1_AccountLimits_LimitsDefinition">AccountLimits::LimitsDefinition</a>&lt;<a href="XUS.md#0x1_XUS">XUS</a>&gt;&gt;(@DiemRoot);
</code></pre>


<code>LimitsDefinition&lt;<a href="XUS.md#0x1_XUS">XUS</a>&gt;</code> is not published at any other address


<pre><code><b>invariant</b> <b>forall</b> addr: address <b>where</b> <b>exists</b>&lt;<a href="AccountLimits.md#0x1_AccountLimits_LimitsDefinition">AccountLimits::LimitsDefinition</a>&lt;<a href="XUS.md#0x1_XUS">XUS</a>&gt;&gt;(addr):
    addr == @DiemRoot;
</code></pre>


[//]: # ("File containing references which can be used from documentation")
[ACCESS_CONTROL]: https://github.com/diem/dip/blob/main/dips/dip-2.md
[ROLE]: https://github.com/diem/dip/blob/main/dips/dip-2.md#roles
[PERMISSION]: https://github.com/diem/dip/blob/main/dips/dip-2.md#permissions
