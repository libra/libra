
<a name="0x1_Diem"></a>

# Module `0x1::Diem`

The <code><a href="Diem.md#0x1_Diem">Diem</a></code> module describes the concept of a coin in the Diem framework. It introduces the
resource <code><a href="Diem.md#0x1_Diem_Diem">Diem::Diem</a>&lt;CoinType&gt;</code>, representing a coin of given coin type.
The module defines functions operating on coins as well as functionality like
minting and burning of coins.


-  [Struct `Diem`](#0x1_Diem_Diem)
-  [Resource `MintCapability`](#0x1_Diem_MintCapability)
-  [Resource `BurnCapability`](#0x1_Diem_BurnCapability)
-  [Struct `MintEvent`](#0x1_Diem_MintEvent)
-  [Struct `BurnEvent`](#0x1_Diem_BurnEvent)
-  [Struct `PreburnEvent`](#0x1_Diem_PreburnEvent)
-  [Struct `CancelBurnEvent`](#0x1_Diem_CancelBurnEvent)
-  [Struct `ToXDXExchangeRateUpdateEvent`](#0x1_Diem_ToXDXExchangeRateUpdateEvent)
-  [Resource `CurrencyInfo`](#0x1_Diem_CurrencyInfo)
-  [Resource `Preburn`](#0x1_Diem_Preburn)
-  [Struct `PreburnWithMetadata`](#0x1_Diem_PreburnWithMetadata)
-  [Resource `PreburnQueue`](#0x1_Diem_PreburnQueue)
-  [Constants](#@Constants_0)
-  [Function `initialize`](#0x1_Diem_initialize)
-  [Function `publish_burn_capability`](#0x1_Diem_publish_burn_capability)
-  [Function `mint`](#0x1_Diem_mint)
-  [Function `burn`](#0x1_Diem_burn)
-  [Function `cancel_burn`](#0x1_Diem_cancel_burn)
-  [Function `mint_with_capability`](#0x1_Diem_mint_with_capability)
-  [Function `preburn_with_resource`](#0x1_Diem_preburn_with_resource)
-  [Function `create_preburn`](#0x1_Diem_create_preburn)
-  [Function `publish_preburn_queue`](#0x1_Diem_publish_preburn_queue)
-  [Function `publish_preburn_queue_to_account`](#0x1_Diem_publish_preburn_queue_to_account)
-  [Function `upgrade_preburn`](#0x1_Diem_upgrade_preburn)
-  [Function `add_preburn_to_queue`](#0x1_Diem_add_preburn_to_queue)
-  [Function `preburn_to`](#0x1_Diem_preburn_to)
-  [Function `remove_preburn_from_queue`](#0x1_Diem_remove_preburn_from_queue)
-  [Function `burn_with_capability`](#0x1_Diem_burn_with_capability)
-  [Function `burn_with_resource_cap`](#0x1_Diem_burn_with_resource_cap)
-  [Function `cancel_burn_with_capability`](#0x1_Diem_cancel_burn_with_capability)
-  [Function `burn_now`](#0x1_Diem_burn_now)
-  [Function `remove_burn_capability`](#0x1_Diem_remove_burn_capability)
-  [Function `preburn_value`](#0x1_Diem_preburn_value)
-  [Function `zero`](#0x1_Diem_zero)
-  [Function `value`](#0x1_Diem_value)
-  [Function `split`](#0x1_Diem_split)
-  [Function `withdraw`](#0x1_Diem_withdraw)
-  [Function `withdraw_all`](#0x1_Diem_withdraw_all)
-  [Function `join`](#0x1_Diem_join)
-  [Function `deposit`](#0x1_Diem_deposit)
-  [Function `destroy_zero`](#0x1_Diem_destroy_zero)
-  [Function `register_currency`](#0x1_Diem_register_currency)
-  [Function `register_SCS_currency`](#0x1_Diem_register_SCS_currency)
-  [Function `market_cap`](#0x1_Diem_market_cap)
-  [Function `approx_xdx_for_value`](#0x1_Diem_approx_xdx_for_value)
-  [Function `approx_xdx_for_coin`](#0x1_Diem_approx_xdx_for_coin)
-  [Function `is_currency`](#0x1_Diem_is_currency)
-  [Function `is_SCS_currency`](#0x1_Diem_is_SCS_currency)
-  [Function `is_synthetic_currency`](#0x1_Diem_is_synthetic_currency)
-  [Function `scaling_factor`](#0x1_Diem_scaling_factor)
-  [Function `fractional_part`](#0x1_Diem_fractional_part)
-  [Function `currency_code`](#0x1_Diem_currency_code)
-  [Function `update_xdx_exchange_rate`](#0x1_Diem_update_xdx_exchange_rate)
-  [Function `xdx_exchange_rate`](#0x1_Diem_xdx_exchange_rate)
-  [Function `update_minting_ability`](#0x1_Diem_update_minting_ability)
-  [Function `assert_is_currency`](#0x1_Diem_assert_is_currency)
-  [Function `assert_is_SCS_currency`](#0x1_Diem_assert_is_SCS_currency)
-  [Module Specification](#@Module_Specification_1)
    -  [Access Control](#@Access_Control_2)
        -  [Minting](#@Minting_3)
        -  [Burning](#@Burning_4)
        -  [Preburning](#@Preburning_5)
        -  [Update Exchange Rates](#@Update_Exchange_Rates_6)
    -  [Helper Functions](#@Helper_Functions_7)


<pre><code><b>use</b> <a href="CoreAddresses.md#0x1_CoreAddresses">0x1::CoreAddresses</a>;
<b>use</b> <a href="DiemTimestamp.md#0x1_DiemTimestamp">0x1::DiemTimestamp</a>;
<b>use</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors">0x1::Errors</a>;
<b>use</b> <a href="../../../../../../move-stdlib/docs/Event.md#0x1_Event">0x1::Event</a>;
<b>use</b> <a href="../../../../../../move-stdlib/docs/FixedPoint32.md#0x1_FixedPoint32">0x1::FixedPoint32</a>;
<b>use</b> <a href="RegisteredCurrencies.md#0x1_RegisteredCurrencies">0x1::RegisteredCurrencies</a>;
<b>use</b> <a href="Roles.md#0x1_Roles">0x1::Roles</a>;
<b>use</b> <a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer">0x1::Signer</a>;
<b>use</b> <a href="../../../../../../move-stdlib/docs/Vector.md#0x1_Vector">0x1::Vector</a>;
</code></pre>



<a name="0x1_Diem_Diem"></a>

## Struct `Diem`

The <code><a href="Diem.md#0x1_Diem">Diem</a></code> resource defines the Diem coin for each currency in
Diem. Each "coin" is coupled with a type <code>CoinType</code> specifying the
currency of the coin, and a <code>value</code> field specifying the value
of the coin (in the base units of the currency <code>CoinType</code>
and specified in the <code><a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a></code> resource for that <code>CoinType</code>
published under the <code>@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a></code> account address).


<pre><code><b>struct</b> <a href="Diem.md#0x1_Diem">Diem</a>&lt;CoinType&gt; has store
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>value: u64</code>
</dt>
<dd>
 The value of this coin in the base units for <code>CoinType</code>
</dd>
</dl>


</details>

<a name="0x1_Diem_MintCapability"></a>

## Resource `MintCapability`

The <code><a href="Diem.md#0x1_Diem_MintCapability">MintCapability</a></code> resource defines a capability to allow minting
of coins of <code>CoinType</code> currency by the holder of this capability.
This capability is held only either by the <code>@TreasuryCompliance</code>
account or the <code>DiemFramework::XDX</code> module (and <code>@DiemRoot</code> in testnet).


<pre><code><b>struct</b> <a href="Diem.md#0x1_Diem_MintCapability">MintCapability</a>&lt;CoinType&gt; has store, key
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

<a name="0x1_Diem_BurnCapability"></a>

## Resource `BurnCapability`

The <code><a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a></code> resource defines a capability to allow coins
of <code>CoinType</code> currency to be burned by the holder of it.


<pre><code><b>struct</b> <a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>&lt;CoinType&gt; has store, key
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

<a name="0x1_Diem_MintEvent"></a>

## Struct `MintEvent`

A <code><a href="Diem.md#0x1_Diem_MintEvent">MintEvent</a></code> is emitted every time a Diem coin is minted. This
contains the <code>amount</code> minted (in base units of the currency being
minted) along with the <code>currency_code</code> for the coin(s) being
minted, and that is defined in the <code>currency_code</code> field of the
<code><a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a></code> resource for the currency.


<pre><code><b>struct</b> <a href="Diem.md#0x1_Diem_MintEvent">MintEvent</a> has drop, store
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>amount: u64</code>
</dt>
<dd>
 Funds added to the system
</dd>
<dt>
<code>currency_code: vector&lt;u8&gt;</code>
</dt>
<dd>
 ASCII encoded symbol for the coin type (e.g., "XDX")
</dd>
</dl>


</details>

<a name="0x1_Diem_BurnEvent"></a>

## Struct `BurnEvent`

A <code><a href="Diem.md#0x1_Diem_BurnEvent">BurnEvent</a></code> is emitted every time a non-synthetic Diem coin
(i.e., a Diem coin with false <code>is_synthetic</code> field) is
burned. It contains the <code>amount</code> burned in base units for the
currency, along with the <code>currency_code</code> for the coins being burned
(and as defined in the <code><a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a></code> resource for that currency).
It also contains the <code>preburn_address</code> from which the coin is
extracted for burning.


<pre><code><b>struct</b> <a href="Diem.md#0x1_Diem_BurnEvent">BurnEvent</a> has drop, store
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>amount: u64</code>
</dt>
<dd>
 Funds removed from the system
</dd>
<dt>
<code>currency_code: vector&lt;u8&gt;</code>
</dt>
<dd>
 ASCII encoded symbol for the coin type (e.g., "XDX")
</dd>
<dt>
<code>preburn_address: address</code>
</dt>
<dd>
 Address with the <code><a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a></code> resource that stored the now-burned funds
</dd>
</dl>


</details>

<a name="0x1_Diem_PreburnEvent"></a>

## Struct `PreburnEvent`

A <code><a href="Diem.md#0x1_Diem_PreburnEvent">PreburnEvent</a></code> is emitted every time an <code>amount</code> of funds with
a coin type <code>currency_code</code> is enqueued in the <code><a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a></code> resource under
the account at the address <code>preburn_address</code>.


<pre><code><b>struct</b> <a href="Diem.md#0x1_Diem_PreburnEvent">PreburnEvent</a> has drop, store
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>amount: u64</code>
</dt>
<dd>
 The amount of funds waiting to be removed (burned) from the system
</dd>
<dt>
<code>currency_code: vector&lt;u8&gt;</code>
</dt>
<dd>
 ASCII encoded symbol for the coin type (e.g., "XDX")
</dd>
<dt>
<code>preburn_address: address</code>
</dt>
<dd>
 Address with the <code><a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a></code> resource that now holds the funds
</dd>
</dl>


</details>

<a name="0x1_Diem_CancelBurnEvent"></a>

## Struct `CancelBurnEvent`

A <code><a href="Diem.md#0x1_Diem_CancelBurnEvent">CancelBurnEvent</a></code> is emitted every time funds of <code>amount</code> in a <code><a href="Diem.md#0x1_Diem_Preburn">Preburn</a></code>
resource held in a <code><a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a></code> at <code>preburn_address</code> is canceled (removed from the
preburn queue, but not burned). The currency of the funds is given by the
<code>currency_code</code> as defined in the <code><a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a></code> for that currency.


<pre><code><b>struct</b> <a href="Diem.md#0x1_Diem_CancelBurnEvent">CancelBurnEvent</a> has drop, store
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>amount: u64</code>
</dt>
<dd>
 The amount of funds returned
</dd>
<dt>
<code>currency_code: vector&lt;u8&gt;</code>
</dt>
<dd>
 ASCII encoded symbol for the coin type (e.g., "XDX")
</dd>
<dt>
<code>preburn_address: address</code>
</dt>
<dd>
 Address of the <code><a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a></code> resource that held the now-returned funds.
</dd>
</dl>


</details>

<a name="0x1_Diem_ToXDXExchangeRateUpdateEvent"></a>

## Struct `ToXDXExchangeRateUpdateEvent`

An <code><a href="Diem.md#0x1_Diem_ToXDXExchangeRateUpdateEvent">ToXDXExchangeRateUpdateEvent</a></code> is emitted every time the to-XDX exchange
rate for the currency given by <code>currency_code</code> is updated.


<pre><code><b>struct</b> <a href="Diem.md#0x1_Diem_ToXDXExchangeRateUpdateEvent">ToXDXExchangeRateUpdateEvent</a> has drop, store
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>currency_code: vector&lt;u8&gt;</code>
</dt>
<dd>
 The currency code of the currency whose exchange rate was updated.
</dd>
<dt>
<code>new_to_xdx_exchange_rate: u64</code>
</dt>
<dd>
 The new on-chain to-XDX exchange rate between the
 <code>currency_code</code> currency and XDX. Represented in conversion
 between the (on-chain) base-units for the currency and microdiem.
</dd>
</dl>


</details>

<a name="0x1_Diem_CurrencyInfo"></a>

## Resource `CurrencyInfo`

The <code><a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;</code> resource stores the various
pieces of information needed for a currency (<code>CoinType</code>) that is
registered on-chain. This resource _must_ be published under the
address given by <code>@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a></code> in order for the registration of
<code>CoinType</code> as a recognized currency on-chain to be successful. At
the time of registration, the <code><a href="Diem.md#0x1_Diem_MintCapability">MintCapability</a>&lt;CoinType&gt;</code> and
<code><a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>&lt;CoinType&gt;</code> capabilities are returned to the caller.
Unless they are specified otherwise the fields in this resource are immutable.


<pre><code><b>struct</b> <a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt; has key
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>total_value: u128</code>
</dt>
<dd>
 The total value for the currency represented by <code>CoinType</code>. Mutable.
</dd>
<dt>
<code>preburn_value: u64</code>
</dt>
<dd>
 Value of funds that are in the process of being burned.  Mutable.
</dd>
<dt>
<code>to_xdx_exchange_rate: <a href="../../../../../../move-stdlib/docs/FixedPoint32.md#0x1_FixedPoint32_FixedPoint32">FixedPoint32::FixedPoint32</a></code>
</dt>
<dd>
 The (rough) exchange rate from <code>CoinType</code> to <code><a href="XDX.md#0x1_XDX">XDX</a></code>. Mutable.
</dd>
<dt>
<code>is_synthetic: bool</code>
</dt>
<dd>
 Holds whether or not this currency is synthetic (contributes to the
 off-chain reserve) or not. An example of such a synthetic
currency would be the XDX.
</dd>
<dt>
<code>scaling_factor: u64</code>
</dt>
<dd>
 The scaling factor for the coin (i.e. the amount to divide by
 to get to the human-readable representation for this currency).
 e.g. 10^6 for <code><a href="XUS.md#0x1_XUS">XUS</a></code>
</dd>
<dt>
<code>fractional_part: u64</code>
</dt>
<dd>
 The smallest fractional part (number of decimal places) to be
 used in the human-readable representation for the currency (e.g.
 10^2 for <code><a href="XUS.md#0x1_XUS">XUS</a></code> cents)
</dd>
<dt>
<code>currency_code: vector&lt;u8&gt;</code>
</dt>
<dd>
 The code symbol for this <code>CoinType</code>. ASCII encoded.
 e.g. for "XDX" this is x"584458". No character limit.
</dd>
<dt>
<code>can_mint: bool</code>
</dt>
<dd>
 Minting of new currency of CoinType is allowed only if this field is true.
 We may want to disable the ability to mint further coins of a
 currency while that currency is still around. This allows us to
 keep the currency in circulation while disallowing further
 creation of coins in the <code>CoinType</code> currency. Mutable.
</dd>
<dt>
<code>mint_events: <a href="../../../../../../move-stdlib/docs/Event.md#0x1_Event_EventHandle">Event::EventHandle</a>&lt;<a href="Diem.md#0x1_Diem_MintEvent">Diem::MintEvent</a>&gt;</code>
</dt>
<dd>
 Event stream for minting and where <code><a href="Diem.md#0x1_Diem_MintEvent">MintEvent</a></code>s will be emitted.
</dd>
<dt>
<code>burn_events: <a href="../../../../../../move-stdlib/docs/Event.md#0x1_Event_EventHandle">Event::EventHandle</a>&lt;<a href="Diem.md#0x1_Diem_BurnEvent">Diem::BurnEvent</a>&gt;</code>
</dt>
<dd>
 Event stream for burning, and where <code><a href="Diem.md#0x1_Diem_BurnEvent">BurnEvent</a></code>s will be emitted.
</dd>
<dt>
<code>preburn_events: <a href="../../../../../../move-stdlib/docs/Event.md#0x1_Event_EventHandle">Event::EventHandle</a>&lt;<a href="Diem.md#0x1_Diem_PreburnEvent">Diem::PreburnEvent</a>&gt;</code>
</dt>
<dd>
 Event stream for preburn requests, and where all
 <code><a href="Diem.md#0x1_Diem_PreburnEvent">PreburnEvent</a></code>s for this <code>CoinType</code> will be emitted.
</dd>
<dt>
<code>cancel_burn_events: <a href="../../../../../../move-stdlib/docs/Event.md#0x1_Event_EventHandle">Event::EventHandle</a>&lt;<a href="Diem.md#0x1_Diem_CancelBurnEvent">Diem::CancelBurnEvent</a>&gt;</code>
</dt>
<dd>
 Event stream for all cancelled preburn requests for this
 <code>CoinType</code>.
</dd>
<dt>
<code>exchange_rate_update_events: <a href="../../../../../../move-stdlib/docs/Event.md#0x1_Event_EventHandle">Event::EventHandle</a>&lt;<a href="Diem.md#0x1_Diem_ToXDXExchangeRateUpdateEvent">Diem::ToXDXExchangeRateUpdateEvent</a>&gt;</code>
</dt>
<dd>
 Event stream for emiting exchange rate change events
</dd>
</dl>


</details>

<details>
<summary>Specification</summary>

Data structure invariant for CurrencyInfo.  Asserts that <code><a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>.scaling_factor</code>
is always greater than 0 and not greater than <code><a href="Diem.md#0x1_Diem_MAX_SCALING_FACTOR">MAX_SCALING_FACTOR</a></code>


<pre><code><b>invariant</b> 0 &lt; scaling_factor && <a href="Diem.md#0x1_Diem_scaling_factor">scaling_factor</a> &lt;= <a href="Diem.md#0x1_Diem_MAX_SCALING_FACTOR">MAX_SCALING_FACTOR</a>;
</code></pre>



</details>

<a name="0x1_Diem_Preburn"></a>

## Resource `Preburn`

A holding area where funds that will subsequently be burned wait while their underlying
assets are moved off-chain.
This resource can only be created by the holder of a <code><a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a></code>
or during an upgrade process to the <code><a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a></code> by a designated
dealer. An account that contains this address has the authority to
initiate a burn request. A burn request can be resolved by the holder
of a <code><a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a></code> by either (1) burning the funds, or (2) returning
the funds to the account that initiated the burn request.


<pre><code><b>struct</b> <a href="Diem.md#0x1_Diem_Preburn">Preburn</a>&lt;CoinType&gt; has store, key
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>to_burn: <a href="Diem.md#0x1_Diem_Diem">Diem::Diem</a>&lt;CoinType&gt;</code>
</dt>
<dd>
 A single pending burn amount. This is an element in the
 <code><a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a></code> resource published under each Designated Dealer account.
</dd>
</dl>


</details>

<a name="0x1_Diem_PreburnWithMetadata"></a>

## Struct `PreburnWithMetadata`

A preburn request, along with (an opaque to Move) metadata that is
associated with the preburn request.


<pre><code><b>struct</b> <a href="Diem.md#0x1_Diem_PreburnWithMetadata">PreburnWithMetadata</a>&lt;CoinType&gt; has store
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>preburn: <a href="Diem.md#0x1_Diem_Preburn">Diem::Preburn</a>&lt;CoinType&gt;</code>
</dt>
<dd>

</dd>
<dt>
<code>metadata: vector&lt;u8&gt;</code>
</dt>
<dd>

</dd>
</dl>


</details>

<a name="0x1_Diem_PreburnQueue"></a>

## Resource `PreburnQueue`

A queue of preburn requests. This is a FIFO queue whose elements
are indexed by the value held within each preburn resource in the
<code>preburns</code> field. When burning or cancelling a burn of a given
<code>amount</code>, the <code><a href="Diem.md#0x1_Diem_Preburn">Preburn</a></code> resource with with the smallest index in this
queue matching <code>amount</code> in its <code>to_burn</code> coin's <code>value</code> field will be
removed and its contents either (1) burned, or (2) returned
back to the holding DD's account balance. Every <code><a href="Diem.md#0x1_Diem_Preburn">Preburn</a></code> resource in
the <code><a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a></code> must have a nonzero coin value within it.
This resource can be created by either the TreasuryCompliance
account, or during the upgrade process, by a designated dealer with an
existing <code><a href="Diem.md#0x1_Diem_Preburn">Preburn</a></code> resource in <code>CoinType</code>


<pre><code><b>struct</b> <a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt; has key
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>preburns: vector&lt;<a href="Diem.md#0x1_Diem_PreburnWithMetadata">Diem::PreburnWithMetadata</a>&lt;CoinType&gt;&gt;</code>
</dt>
<dd>
 The queue of preburn requests
</dd>
</dl>


</details>

<details>
<summary>Specification</summary>


The number of outstanding preburn requests is bounded.


<pre><code><b>invariant</b> len(preburns) &lt;= <a href="Diem.md#0x1_Diem_MAX_OUTSTANDING_PREBURNS">MAX_OUTSTANDING_PREBURNS</a>;
</code></pre>


No preburn request can have a zero value.
The <code>value</code> field of any coin in a <code><a href="Diem.md#0x1_Diem_Preburn">Preburn</a></code> resource
within this field must be nonzero.


<pre><code><b>invariant</b> <b>forall</b> i in 0..len(preburns): preburns[i].preburn.to_burn.value &gt; 0;
</code></pre>



</details>

<a name="@Constants_0"></a>

## Constants


<a name="0x1_Diem_MAX_U64"></a>

Maximum u64 value.


<pre><code><b>const</b> <a href="Diem.md#0x1_Diem_MAX_U64">MAX_U64</a>: u64 = 18446744073709551615;
</code></pre>



<a name="0x1_Diem_MAX_U128"></a>

Maximum u128 value.


<pre><code><b>const</b> <a href="Diem.md#0x1_Diem_MAX_U128">MAX_U128</a>: u128 = 340282366920938463463374607431768211455;
</code></pre>



<a name="0x1_Diem_ECURRENCY_INFO"></a>

A property expected of a <code><a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a></code> resource didn't hold


<pre><code><b>const</b> <a href="Diem.md#0x1_Diem_ECURRENCY_INFO">ECURRENCY_INFO</a>: u64 = 1;
</code></pre>



<a name="0x1_Diem_EAMOUNT_EXCEEDS_COIN_VALUE"></a>

A withdrawal greater than the value of the coin was attempted.


<pre><code><b>const</b> <a href="Diem.md#0x1_Diem_EAMOUNT_EXCEEDS_COIN_VALUE">EAMOUNT_EXCEEDS_COIN_VALUE</a>: u64 = 10;
</code></pre>



<a name="0x1_Diem_EBURN_CAPABILITY"></a>

A <code><a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a></code> resource is in an unexpected state.


<pre><code><b>const</b> <a href="Diem.md#0x1_Diem_EBURN_CAPABILITY">EBURN_CAPABILITY</a>: u64 = 0;
</code></pre>



<a name="0x1_Diem_ECOIN"></a>

A property expected of the coin provided didn't hold


<pre><code><b>const</b> <a href="Diem.md#0x1_Diem_ECOIN">ECOIN</a>: u64 = 7;
</code></pre>



<a name="0x1_Diem_EDESTRUCTION_OF_NONZERO_COIN"></a>

The destruction of a non-zero coin was attempted. Non-zero coins must be burned.


<pre><code><b>const</b> <a href="Diem.md#0x1_Diem_EDESTRUCTION_OF_NONZERO_COIN">EDESTRUCTION_OF_NONZERO_COIN</a>: u64 = 8;
</code></pre>



<a name="0x1_Diem_EIS_SYNTHETIC_CURRENCY"></a>

The currency specified is a synthetic (non-fiat) currency


<pre><code><b>const</b> <a href="Diem.md#0x1_Diem_EIS_SYNTHETIC_CURRENCY">EIS_SYNTHETIC_CURRENCY</a>: u64 = 6;
</code></pre>



<a name="0x1_Diem_EMINTING_NOT_ALLOWED"></a>

Minting is not allowed for the specified currency


<pre><code><b>const</b> <a href="Diem.md#0x1_Diem_EMINTING_NOT_ALLOWED">EMINTING_NOT_ALLOWED</a>: u64 = 5;
</code></pre>



<a name="0x1_Diem_EMINT_CAPABILITY"></a>

A property expected of <code><a href="Diem.md#0x1_Diem_MintCapability">MintCapability</a></code> didn't hold


<pre><code><b>const</b> <a href="Diem.md#0x1_Diem_EMINT_CAPABILITY">EMINT_CAPABILITY</a>: u64 = 9;
</code></pre>



<a name="0x1_Diem_EPREBURN"></a>

A property expected of a <code><a href="Diem.md#0x1_Diem_Preburn">Preburn</a></code> resource didn't hold


<pre><code><b>const</b> <a href="Diem.md#0x1_Diem_EPREBURN">EPREBURN</a>: u64 = 2;
</code></pre>



<a name="0x1_Diem_EPREBURN_EMPTY"></a>

A burn was attempted on <code><a href="Diem.md#0x1_Diem_Preburn">Preburn</a></code> resource that cointained no coins


<pre><code><b>const</b> <a href="Diem.md#0x1_Diem_EPREBURN_EMPTY">EPREBURN_EMPTY</a>: u64 = 4;
</code></pre>



<a name="0x1_Diem_EPREBURN_NOT_FOUND"></a>

A preburn with a matching amount in the preburn queue was not found.


<pre><code><b>const</b> <a href="Diem.md#0x1_Diem_EPREBURN_NOT_FOUND">EPREBURN_NOT_FOUND</a>: u64 = 12;
</code></pre>



<a name="0x1_Diem_EPREBURN_OCCUPIED"></a>

The preburn slot is already occupied with coins to be burned.


<pre><code><b>const</b> <a href="Diem.md#0x1_Diem_EPREBURN_OCCUPIED">EPREBURN_OCCUPIED</a>: u64 = 3;
</code></pre>



<a name="0x1_Diem_EPREBURN_QUEUE"></a>

A property expected of the <code><a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a></code> resource didn't hold.


<pre><code><b>const</b> <a href="Diem.md#0x1_Diem_EPREBURN_QUEUE">EPREBURN_QUEUE</a>: u64 = 11;
</code></pre>



<a name="0x1_Diem_MAX_OUTSTANDING_PREBURNS"></a>

The maximum number of preburn requests that can be outstanding for a
given designated dealer/currency.


<pre><code><b>const</b> <a href="Diem.md#0x1_Diem_MAX_OUTSTANDING_PREBURNS">MAX_OUTSTANDING_PREBURNS</a>: u64 = 256;
</code></pre>



<a name="0x1_Diem_MAX_SCALING_FACTOR"></a>

The maximum value for <code><a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>.scaling_factor</code>


<pre><code><b>const</b> <a href="Diem.md#0x1_Diem_MAX_SCALING_FACTOR">MAX_SCALING_FACTOR</a>: u64 = 10000000000;
</code></pre>



<a name="0x1_Diem_initialize"></a>

## Function `initialize`

Initialization of the <code><a href="Diem.md#0x1_Diem">Diem</a></code> module. Initializes the set of
registered currencies in the <code>DiemFramework::RegisteredCurrencies</code> on-chain
config, and publishes the <code>CurrencyRegistrationCapability</code> under the
<code>@DiemRoot</code>. This can only be called from genesis.


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_initialize">initialize</a>(dr_account: &signer)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_initialize">initialize</a>(
    dr_account: &signer,
) {
    <a href="DiemTimestamp.md#0x1_DiemTimestamp_assert_genesis">DiemTimestamp::assert_genesis</a>();
    // Operational constraint
    <a href="CoreAddresses.md#0x1_CoreAddresses_assert_diem_root">CoreAddresses::assert_diem_root</a>(dr_account);
    <a href="RegisteredCurrencies.md#0x1_RegisteredCurrencies_initialize">RegisteredCurrencies::initialize</a>(dr_account);
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="DiemTimestamp.md#0x1_DiemTimestamp_AbortsIfNotGenesis">DiemTimestamp::AbortsIfNotGenesis</a>;
<b>include</b> <a href="CoreAddresses.md#0x1_CoreAddresses_AbortsIfNotDiemRoot">CoreAddresses::AbortsIfNotDiemRoot</a>{account: dr_account};
<b>include</b> <a href="RegisteredCurrencies.md#0x1_RegisteredCurrencies_InitializeAbortsIf">RegisteredCurrencies::InitializeAbortsIf</a>;
<b>include</b> <a href="RegisteredCurrencies.md#0x1_RegisteredCurrencies_InitializeEnsures">RegisteredCurrencies::InitializeEnsures</a>;
</code></pre>



</details>

<a name="0x1_Diem_publish_burn_capability"></a>

## Function `publish_burn_capability`

Publishes the <code><a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a></code> <code>cap</code> for the <code>CoinType</code> currency under <code>account</code>. <code>CoinType</code>
must be a registered currency type. The caller must pass a treasury compliance account.


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_publish_burn_capability">publish_burn_capability</a>&lt;CoinType&gt;(tc_account: &signer, cap: <a href="Diem.md#0x1_Diem_BurnCapability">Diem::BurnCapability</a>&lt;CoinType&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_publish_burn_capability">publish_burn_capability</a>&lt;CoinType&gt;(
    tc_account: &signer,
    cap: <a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>&lt;CoinType&gt;,
) {
    <a href="Roles.md#0x1_Roles_assert_treasury_compliance">Roles::assert_treasury_compliance</a>(tc_account);
    <a href="Diem.md#0x1_Diem_assert_is_currency">assert_is_currency</a>&lt;CoinType&gt;();
    <b>assert</b>(
        !<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>&lt;CoinType&gt;&gt;(<a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_address_of">Signer::address_of</a>(tc_account)),
        <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_already_published">Errors::already_published</a>(<a href="Diem.md#0x1_Diem_EBURN_CAPABILITY">EBURN_CAPABILITY</a>)
    );
    move_to(tc_account, cap)
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>aborts_if</b> !<a href="Diem.md#0x1_Diem_spec_is_currency">spec_is_currency</a>&lt;CoinType&gt;();
<b>include</b> <a href="Diem.md#0x1_Diem_PublishBurnCapAbortsIfs">PublishBurnCapAbortsIfs</a>&lt;CoinType&gt;;
</code></pre>




<a name="0x1_Diem_PublishBurnCapAbortsIfs"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_PublishBurnCapAbortsIfs">PublishBurnCapAbortsIfs</a>&lt;CoinType&gt; {
    tc_account: &signer;
}
</code></pre>


Must abort if tc_account does not have the TreasuryCompliance role.
Only a TreasuryCompliance account can have the BurnCapability [[H3]][PERMISSION].


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_PublishBurnCapAbortsIfs">PublishBurnCapAbortsIfs</a>&lt;CoinType&gt; {
    <b>include</b> <a href="Roles.md#0x1_Roles_AbortsIfNotTreasuryCompliance">Roles::AbortsIfNotTreasuryCompliance</a>{account: tc_account};
    <b>aborts_if</b> <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>&lt;CoinType&gt;&gt;(<a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(tc_account)) <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a>;
}
</code></pre>




<a name="0x1_Diem_PublishBurnCapEnsures"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_PublishBurnCapEnsures">PublishBurnCapEnsures</a>&lt;CoinType&gt; {
    tc_account: &signer;
    <b>ensures</b> <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>&lt;CoinType&gt;&gt;(<a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(tc_account));
}
</code></pre>



</details>

<a name="0x1_Diem_mint"></a>

## Function `mint`

Mints <code>amount</code> of currency. The <code>account</code> must hold a
<code><a href="Diem.md#0x1_Diem_MintCapability">MintCapability</a>&lt;CoinType&gt;</code> at the top-level in order for this call
to be successful.


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_mint">mint</a>&lt;CoinType&gt;(account: &signer, value: u64): <a href="Diem.md#0x1_Diem_Diem">Diem::Diem</a>&lt;CoinType&gt;
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_mint">mint</a>&lt;CoinType&gt;(account: &signer, value: u64): <a href="Diem.md#0x1_Diem">Diem</a>&lt;CoinType&gt;
<b>acquires</b> <a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>, <a href="Diem.md#0x1_Diem_MintCapability">MintCapability</a> {
    <b>let</b> addr = <a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_address_of">Signer::address_of</a>(account);
    <b>assert</b>(<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_MintCapability">MintCapability</a>&lt;CoinType&gt;&gt;(addr), <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_requires_capability">Errors::requires_capability</a>(<a href="Diem.md#0x1_Diem_EMINT_CAPABILITY">EMINT_CAPABILITY</a>));
    <a href="Diem.md#0x1_Diem_mint_with_capability">mint_with_capability</a>(
        value,
        borrow_global&lt;<a href="Diem.md#0x1_Diem_MintCapability">MintCapability</a>&lt;CoinType&gt;&gt;(addr)
    )
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>modifies</b> <b>global</b>&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>);
<b>ensures</b> <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>);
</code></pre>


Must abort if the account does not have the MintCapability [[H1]][PERMISSION].


<pre><code><b>aborts_if</b> !<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_MintCapability">MintCapability</a>&lt;CoinType&gt;&gt;(<a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(account)) <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_CAPABILITY">Errors::REQUIRES_CAPABILITY</a>;
<b>include</b> <a href="Diem.md#0x1_Diem_MintAbortsIf">MintAbortsIf</a>&lt;CoinType&gt;;
<b>include</b> <a href="Diem.md#0x1_Diem_MintEnsures">MintEnsures</a>&lt;CoinType&gt;;
</code></pre>



</details>

<a name="0x1_Diem_burn"></a>

## Function `burn`

Burns the coins held in the first <code><a href="Diem.md#0x1_Diem_Preburn">Preburn</a></code> request in the <code><a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a></code>
resource held under <code>preburn_address</code> that is equal to <code>amount</code>.
Calls to this functions will fail if the <code>account</code> does not have a
published <code><a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a></code> for the <code>CoinType</code> published under it, or if
there is not a <code><a href="Diem.md#0x1_Diem_Preburn">Preburn</a></code> request in the <code><a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a></code> that does not
equal <code>amount</code>.


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_burn">burn</a>&lt;CoinType&gt;(account: &signer, preburn_address: address, amount: u64)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_burn">burn</a>&lt;CoinType&gt;(
    account: &signer,
    preburn_address: address,
    amount: u64,
) <b>acquires</b> <a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>, <a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>, <a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a> {
    <b>let</b> addr = <a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_address_of">Signer::address_of</a>(account);
    <b>assert</b>(<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>&lt;CoinType&gt;&gt;(addr), <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_requires_capability">Errors::requires_capability</a>(<a href="Diem.md#0x1_Diem_EBURN_CAPABILITY">EBURN_CAPABILITY</a>));
    <a href="Diem.md#0x1_Diem_burn_with_capability">burn_with_capability</a>(
        preburn_address,
        borrow_global&lt;<a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>&lt;CoinType&gt;&gt;(addr),
        amount
    )
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="Diem.md#0x1_Diem_BurnAbortsIf">BurnAbortsIf</a>&lt;CoinType&gt;;
<b>include</b> <a href="Diem.md#0x1_Diem_BurnEnsures">BurnEnsures</a>&lt;CoinType&gt;;
<b>include</b> <a href="Diem.md#0x1_Diem_BurnWithResourceCapEmits">BurnWithResourceCapEmits</a>&lt;CoinType&gt;{preburn: <a href="Diem.md#0x1_Diem_spec_make_preburn">spec_make_preburn</a>(amount)};
</code></pre>




<a name="0x1_Diem_BurnAbortsIf"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_BurnAbortsIf">BurnAbortsIf</a>&lt;CoinType&gt; {
    account: signer;
    preburn_address: address;
}
</code></pre>


Must abort if the account does not have the BurnCapability [[H3]][PERMISSION].


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_BurnAbortsIf">BurnAbortsIf</a>&lt;CoinType&gt; {
    <b>aborts_if</b> !<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>&lt;CoinType&gt;&gt;(<a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(account)) <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_CAPABILITY">Errors::REQUIRES_CAPABILITY</a>;
    <b>include</b> <a href="Diem.md#0x1_Diem_BurnWithCapabilityAbortsIf">BurnWithCapabilityAbortsIf</a>&lt;CoinType&gt;;
}
</code></pre>




<a name="0x1_Diem_BurnEnsures"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_BurnEnsures">BurnEnsures</a>&lt;CoinType&gt; {
    account: signer;
    preburn_address: address;
    <b>include</b> <a href="Diem.md#0x1_Diem_BurnWithCapabilityEnsures">BurnWithCapabilityEnsures</a>&lt;CoinType&gt;;
}
</code></pre>




<a name="0x1_Diem_AbortsIfNoPreburnQueue"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_AbortsIfNoPreburnQueue">AbortsIfNoPreburnQueue</a>&lt;CoinType&gt; {
    preburn_address: address;
    <b>aborts_if</b> !<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(preburn_address) <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>;
}
</code></pre>



</details>

<a name="0x1_Diem_cancel_burn"></a>

## Function `cancel_burn`

Cancels the <code><a href="Diem.md#0x1_Diem_Preburn">Preburn</a></code> request in the <code><a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a></code> resource held
under the <code>preburn_address</code> with a value equal to <code>amount</code>, and returns the coins.
Calls to this will fail if the sender does not have a published
<code><a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>&lt;CoinType&gt;</code>, or if there is no preburn request
outstanding in the <code><a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a></code> resource under <code>preburn_address</code> with
a value equal to <code>amount</code>.


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_cancel_burn">cancel_burn</a>&lt;CoinType&gt;(account: &signer, preburn_address: address, amount: u64): <a href="Diem.md#0x1_Diem_Diem">Diem::Diem</a>&lt;CoinType&gt;
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_cancel_burn">cancel_burn</a>&lt;CoinType&gt;(
    account: &signer,
    preburn_address: address,
    amount: u64,
): <a href="Diem.md#0x1_Diem">Diem</a>&lt;CoinType&gt; <b>acquires</b> <a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>, <a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>, <a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a> {
    <a href="Diem.md#0x1_Diem_assert_is_currency">assert_is_currency</a>&lt;CoinType&gt;();
    <b>let</b> addr = <a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_address_of">Signer::address_of</a>(account);
    <b>assert</b>(<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>&lt;CoinType&gt;&gt;(addr), <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_requires_capability">Errors::requires_capability</a>(<a href="Diem.md#0x1_Diem_EBURN_CAPABILITY">EBURN_CAPABILITY</a>));
    <a href="Diem.md#0x1_Diem_cancel_burn_with_capability">cancel_burn_with_capability</a>(
        preburn_address,
        borrow_global&lt;<a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>&lt;CoinType&gt;&gt;(addr),
        amount,
    )
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>let</b> currency_info = <b>global</b>&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>);
<b>let</b> post post_currency_info = <b>global</b>&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>);
<b>modifies</b> <b>global</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(preburn_address);
<b>modifies</b> <b>global</b>&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>);
<b>include</b> <a href="Diem.md#0x1_Diem_CancelBurnAbortsIf">CancelBurnAbortsIf</a>&lt;CoinType&gt;;
<b>include</b> <a href="Diem.md#0x1_Diem_CancelBurnWithCapEnsures">CancelBurnWithCapEnsures</a>&lt;CoinType&gt;;
<b>include</b> <a href="Diem.md#0x1_Diem_CancelBurnWithCapEmits">CancelBurnWithCapEmits</a>&lt;CoinType&gt;;
<b>ensures</b> <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>);
<b>ensures</b> <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(preburn_address);
<b>ensures</b> post_currency_info == update_field(
    currency_info,
    preburn_value,
    post_currency_info.preburn_value
);
<b>ensures</b> result.value == amount;
<b>ensures</b> result.value &gt; 0;
</code></pre>




<a name="0x1_Diem_CancelBurnAbortsIf"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_CancelBurnAbortsIf">CancelBurnAbortsIf</a>&lt;CoinType&gt; {
    account: signer;
    preburn_address: address;
    amount: u64;
}
</code></pre>


Must abort if the account does not have the BurnCapability [[H3]][PERMISSION].


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_CancelBurnAbortsIf">CancelBurnAbortsIf</a>&lt;CoinType&gt; {
    <b>aborts_if</b> !<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>&lt;CoinType&gt;&gt;(<a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(account)) <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_CAPABILITY">Errors::REQUIRES_CAPABILITY</a>;
    <b>include</b> <a href="Diem.md#0x1_Diem_CancelBurnWithCapAbortsIf">CancelBurnWithCapAbortsIf</a>&lt;CoinType&gt;;
}
</code></pre>



</details>

<a name="0x1_Diem_mint_with_capability"></a>

## Function `mint_with_capability`

Mint a new <code><a href="Diem.md#0x1_Diem">Diem</a></code> coin of <code>CoinType</code> currency worth <code>value</code>. The
caller must have a reference to a <code><a href="Diem.md#0x1_Diem_MintCapability">MintCapability</a>&lt;CoinType&gt;</code>. Only
the treasury compliance account or the <code>DiemFramework::XDX</code> module can acquire such a
reference.


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_mint_with_capability">mint_with_capability</a>&lt;CoinType&gt;(value: u64, _capability: &<a href="Diem.md#0x1_Diem_MintCapability">Diem::MintCapability</a>&lt;CoinType&gt;): <a href="Diem.md#0x1_Diem_Diem">Diem::Diem</a>&lt;CoinType&gt;
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_mint_with_capability">mint_with_capability</a>&lt;CoinType&gt;(
    value: u64,
    _capability: &<a href="Diem.md#0x1_Diem_MintCapability">MintCapability</a>&lt;CoinType&gt;
): <a href="Diem.md#0x1_Diem">Diem</a>&lt;CoinType&gt; <b>acquires</b> <a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a> {
    <a href="Diem.md#0x1_Diem_assert_is_currency">assert_is_currency</a>&lt;CoinType&gt;();
    <b>let</b> currency_code = <a href="Diem.md#0x1_Diem_currency_code">currency_code</a>&lt;CoinType&gt;();
    // <b>update</b> market cap <b>resource</b> <b>to</b> reflect minting
    <b>let</b> info = borrow_global_mut&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>);
    <b>assert</b>(info.can_mint, <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_invalid_state">Errors::invalid_state</a>(<a href="Diem.md#0x1_Diem_EMINTING_NOT_ALLOWED">EMINTING_NOT_ALLOWED</a>));
    <b>assert</b>(<a href="Diem.md#0x1_Diem_MAX_U128">MAX_U128</a> - info.total_value &gt;= (value <b>as</b> u128), <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_limit_exceeded">Errors::limit_exceeded</a>(<a href="Diem.md#0x1_Diem_ECURRENCY_INFO">ECURRENCY_INFO</a>));
    info.total_value = info.total_value + (value <b>as</b> u128);
    // don't emit mint events for synthetic currenices <b>as</b> this does not
    // change the total value of fiat currencies held on-chain.
    <b>if</b> (!info.is_synthetic) {
        <a href="../../../../../../move-stdlib/docs/Event.md#0x1_Event_emit_event">Event::emit_event</a>(
            &<b>mut</b> info.mint_events,
            <a href="Diem.md#0x1_Diem_MintEvent">MintEvent</a>{
                amount: value,
                currency_code,
            }
        );
    };

    <a href="Diem.md#0x1_Diem">Diem</a>&lt;CoinType&gt; { value }
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>pragma</b> opaque;
<b>modifies</b> <b>global</b>&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>);
<b>ensures</b> <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>);
<b>include</b> <a href="Diem.md#0x1_Diem_MintAbortsIf">MintAbortsIf</a>&lt;CoinType&gt;;
<b>include</b> <a href="Diem.md#0x1_Diem_MintEnsures">MintEnsures</a>&lt;CoinType&gt;;
<b>include</b> <a href="Diem.md#0x1_Diem_MintEmits">MintEmits</a>&lt;CoinType&gt;;
</code></pre>




<a name="0x1_Diem_MintAbortsIf"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_MintAbortsIf">MintAbortsIf</a>&lt;CoinType&gt; {
    value: u64;
    <b>include</b> <a href="Diem.md#0x1_Diem_AbortsIfNoCurrency">AbortsIfNoCurrency</a>&lt;CoinType&gt;;
    <b>aborts_if</b> !<a href="Diem.md#0x1_Diem_spec_currency_info">spec_currency_info</a>&lt;CoinType&gt;().can_mint <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_STATE">Errors::INVALID_STATE</a>;
    <b>aborts_if</b> <a href="Diem.md#0x1_Diem_spec_currency_info">spec_currency_info</a>&lt;CoinType&gt;().total_value + value &gt; max_u128() <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a>;
}
</code></pre>




<a name="0x1_Diem_MintEnsures"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_MintEnsures">MintEnsures</a>&lt;CoinType&gt; {
    value: u64;
    result: <a href="Diem.md#0x1_Diem">Diem</a>&lt;CoinType&gt;;
    <b>let</b> currency_info = <b>global</b>&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>);
    <b>let</b> post post_currency_info = <b>global</b>&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>);
    <b>ensures</b> <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>);
    <b>ensures</b> post_currency_info == update_field(currency_info, total_value, currency_info.total_value + value);
    <b>ensures</b> result.value == value;
}
</code></pre>




<a name="0x1_Diem_MintEmits"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_MintEmits">MintEmits</a>&lt;CoinType&gt; {
    value: u64;
    <b>let</b> currency_info = <b>global</b>&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>);
    <b>let</b> handle = currency_info.mint_events;
    <b>let</b> msg = <a href="Diem.md#0x1_Diem_MintEvent">MintEvent</a>{
        amount: value,
        currency_code: currency_info.currency_code,
    };
    emits msg <b>to</b> handle <b>if</b> !currency_info.is_synthetic;
}
</code></pre>



</details>

<a name="0x1_Diem_preburn_with_resource"></a>

## Function `preburn_with_resource`

Add the <code>coin</code> to the <code>preburn.to_burn</code> field in the <code><a href="Diem.md#0x1_Diem_Preburn">Preburn</a></code> resource
held in the preburn queue at the address <code>preburn_address</code> if it is
empty, otherwise raise a <code><a href="Diem.md#0x1_Diem_EPREBURN_OCCUPIED">EPREBURN_OCCUPIED</a></code> Error. Emits a
<code><a href="Diem.md#0x1_Diem_PreburnEvent">PreburnEvent</a></code> to the <code>preburn_events</code> event stream in the
<code><a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a></code> for the <code>CoinType</code> passed in. However, if the currency
being preburned is a synthetic currency (<code>is_synthetic = <b>true</b></code>) then no
<code><a href="Diem.md#0x1_Diem_PreburnEvent">PreburnEvent</a></code> will be emitted.


<pre><code><b>fun</b> <a href="Diem.md#0x1_Diem_preburn_with_resource">preburn_with_resource</a>&lt;CoinType&gt;(coin: <a href="Diem.md#0x1_Diem_Diem">Diem::Diem</a>&lt;CoinType&gt;, preburn: &<b>mut</b> <a href="Diem.md#0x1_Diem_Preburn">Diem::Preburn</a>&lt;CoinType&gt;, preburn_address: address)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>fun</b> <a href="Diem.md#0x1_Diem_preburn_with_resource">preburn_with_resource</a>&lt;CoinType&gt;(
    coin: <a href="Diem.md#0x1_Diem">Diem</a>&lt;CoinType&gt;,
    preburn: &<b>mut</b> <a href="Diem.md#0x1_Diem_Preburn">Preburn</a>&lt;CoinType&gt;,
    preburn_address: address,
) <b>acquires</b> <a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a> {
    <b>let</b> coin_value = <a href="Diem.md#0x1_Diem_value">value</a>(&coin);
    // Throw <b>if</b> already occupied
    <b>assert</b>(<a href="Diem.md#0x1_Diem_value">value</a>(&preburn.to_burn) == 0, <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_invalid_state">Errors::invalid_state</a>(<a href="Diem.md#0x1_Diem_EPREBURN_OCCUPIED">EPREBURN_OCCUPIED</a>));
    <a href="Diem.md#0x1_Diem_deposit">deposit</a>(&<b>mut</b> preburn.to_burn, coin);
    <b>let</b> currency_code = <a href="Diem.md#0x1_Diem_currency_code">currency_code</a>&lt;CoinType&gt;();
    <b>let</b> info = borrow_global_mut&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>);
    <b>assert</b>(<a href="Diem.md#0x1_Diem_MAX_U64">MAX_U64</a> - info.preburn_value &gt;= coin_value, <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_limit_exceeded">Errors::limit_exceeded</a>(<a href="Diem.md#0x1_Diem_ECOIN">ECOIN</a>));
    info.preburn_value = info.preburn_value + coin_value;
    // don't emit preburn events for synthetic currenices <b>as</b> this does not
    // change the total value of fiat currencies held on-chain, and
    // therefore no off-chain movement of the backing coins needs <b>to</b> be
    // performed.
    <b>if</b> (!info.is_synthetic) {
        <a href="../../../../../../move-stdlib/docs/Event.md#0x1_Event_emit_event">Event::emit_event</a>(
            &<b>mut</b> info.preburn_events,
            <a href="Diem.md#0x1_Diem_PreburnEvent">PreburnEvent</a>{
                amount: coin_value,
                currency_code,
                preburn_address,
            }
        );
    };
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>modifies</b> <b>global</b>&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>);
<b>ensures</b> <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>);
<b>include</b> <a href="Diem.md#0x1_Diem_PreburnWithResourceAbortsIf">PreburnWithResourceAbortsIf</a>&lt;CoinType&gt;{amount: coin.value};
<b>include</b> <a href="Diem.md#0x1_Diem_PreburnEnsures">PreburnEnsures</a>&lt;CoinType&gt;{amount: coin.value};
<b>include</b> <a href="Diem.md#0x1_Diem_PreburnWithResourceEmits">PreburnWithResourceEmits</a>&lt;CoinType&gt;{amount: coin.value};
</code></pre>




<a name="0x1_Diem_PreburnWithResourceAbortsIf"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_PreburnWithResourceAbortsIf">PreburnWithResourceAbortsIf</a>&lt;CoinType&gt; {
    amount: u64;
    preburn: <a href="Diem.md#0x1_Diem_Preburn">Preburn</a>&lt;CoinType&gt;;
    <b>aborts_if</b> preburn.to_burn.value &gt; 0 <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_STATE">Errors::INVALID_STATE</a>;
    <b>include</b> <a href="Diem.md#0x1_Diem_PreburnAbortsIf">PreburnAbortsIf</a>&lt;CoinType&gt;;
}
</code></pre>




<a name="0x1_Diem_PreburnAbortsIf"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_PreburnAbortsIf">PreburnAbortsIf</a>&lt;CoinType&gt; {
    amount: u64;
    <b>include</b> <a href="Diem.md#0x1_Diem_AbortsIfNoCurrency">AbortsIfNoCurrency</a>&lt;CoinType&gt;;
    <b>aborts_if</b> <a href="Diem.md#0x1_Diem_spec_currency_info">spec_currency_info</a>&lt;CoinType&gt;().preburn_value + amount &gt; <a href="Diem.md#0x1_Diem_MAX_U64">MAX_U64</a> <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a>;
}
</code></pre>




<a name="0x1_Diem_PreburnEnsures"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_PreburnEnsures">PreburnEnsures</a>&lt;CoinType&gt; {
    amount: u64;
    preburn: <a href="Diem.md#0x1_Diem_Preburn">Preburn</a>&lt;CoinType&gt;;
    <b>let</b> info = <a href="Diem.md#0x1_Diem_spec_currency_info">spec_currency_info</a>&lt;CoinType&gt;();
    <b>let</b> post post_info = <a href="Diem.md#0x1_Diem_spec_currency_info">spec_currency_info</a>&lt;CoinType&gt;();
    <b>ensures</b> post_info == update_field(info, preburn_value, info.preburn_value + amount);
}
</code></pre>




<a name="0x1_Diem_PreburnWithResourceEmits"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_PreburnWithResourceEmits">PreburnWithResourceEmits</a>&lt;CoinType&gt; {
    amount: u64;
    preburn_address: address;
    <b>let</b> info = <a href="Diem.md#0x1_Diem_spec_currency_info">spec_currency_info</a>&lt;CoinType&gt;();
    <b>let</b> currency_code = <a href="Diem.md#0x1_Diem_spec_currency_code">spec_currency_code</a>&lt;CoinType&gt;();
    <b>let</b> handle = info.preburn_events;
    <b>let</b> msg = <a href="Diem.md#0x1_Diem_PreburnEvent">PreburnEvent</a> {
        amount,
        currency_code,
        preburn_address,
    };
    emits msg <b>to</b> handle <b>if</b> !info.is_synthetic;
}
</code></pre>



</details>

<a name="0x1_Diem_create_preburn"></a>

## Function `create_preburn`

Create a <code><a href="Diem.md#0x1_Diem_Preburn">Preburn</a>&lt;CoinType&gt;</code> resource.
This is useful for places where a module needs to be able to burn coins
outside of a Designated Dealer, e.g., for transaction fees, or for the XDX reserve.


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_create_preburn">create_preburn</a>&lt;CoinType&gt;(tc_account: &signer): <a href="Diem.md#0x1_Diem_Preburn">Diem::Preburn</a>&lt;CoinType&gt;
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_create_preburn">create_preburn</a>&lt;CoinType&gt;(
    tc_account: &signer
): <a href="Diem.md#0x1_Diem_Preburn">Preburn</a>&lt;CoinType&gt; {
    <a href="Roles.md#0x1_Roles_assert_treasury_compliance">Roles::assert_treasury_compliance</a>(tc_account);
    <a href="Diem.md#0x1_Diem_assert_is_currency">assert_is_currency</a>&lt;CoinType&gt;();
    <a href="Diem.md#0x1_Diem_Preburn">Preburn</a>&lt;CoinType&gt; { to_burn: <a href="Diem.md#0x1_Diem_zero">zero</a>&lt;CoinType&gt;() }
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="Diem.md#0x1_Diem_CreatePreburnAbortsIf">CreatePreburnAbortsIf</a>&lt;CoinType&gt;;
</code></pre>




<a name="0x1_Diem_CreatePreburnAbortsIf"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_CreatePreburnAbortsIf">CreatePreburnAbortsIf</a>&lt;CoinType&gt; {
    tc_account: signer;
    <b>include</b> <a href="Roles.md#0x1_Roles_AbortsIfNotTreasuryCompliance">Roles::AbortsIfNotTreasuryCompliance</a>{account: tc_account};
    <b>include</b> <a href="Diem.md#0x1_Diem_AbortsIfNoCurrency">AbortsIfNoCurrency</a>&lt;CoinType&gt;;
}
</code></pre>



</details>

<a name="0x1_Diem_publish_preburn_queue"></a>

## Function `publish_preburn_queue`

Publish an empty <code><a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a></code> resource under the Designated Dealer
dealer account <code>account</code>.


<pre><code><b>fun</b> <a href="Diem.md#0x1_Diem_publish_preburn_queue">publish_preburn_queue</a>&lt;CoinType&gt;(account: &signer)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>fun</b> <a href="Diem.md#0x1_Diem_publish_preburn_queue">publish_preburn_queue</a>&lt;CoinType&gt;(
    account: &signer
) {
    <b>let</b> account_addr = <a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_address_of">Signer::address_of</a>(account);
    <a href="Roles.md#0x1_Roles_assert_designated_dealer">Roles::assert_designated_dealer</a>(account);
    <a href="Diem.md#0x1_Diem_assert_is_currency">assert_is_currency</a>&lt;CoinType&gt;();
    <b>assert</b>(
        !<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_Preburn">Preburn</a>&lt;CoinType&gt;&gt;(account_addr),
        <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_invalid_state">Errors::invalid_state</a>(<a href="Diem.md#0x1_Diem_EPREBURN">EPREBURN</a>)
    );
    <b>assert</b>(
        !<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(account_addr),
        <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_already_published">Errors::already_published</a>(<a href="Diem.md#0x1_Diem_EPREBURN_QUEUE">EPREBURN_QUEUE</a>)
    );
    move_to(account, <a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt; {
        preburns: <a href="../../../../../../move-stdlib/docs/Vector.md#0x1_Vector_empty">Vector::empty</a>()
    })
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>pragma</b> opaque;
<b>let</b> account_addr = <a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(account);
<b>modifies</b> <b>global</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(account_addr);
<b>aborts_if</b> <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(account_addr) <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a>;
<b>aborts_if</b> <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_Preburn">Preburn</a>&lt;CoinType&gt;&gt;(account_addr) <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_STATE">Errors::INVALID_STATE</a>;
<b>include</b> <a href="Diem.md#0x1_Diem_PublishPreburnQueueAbortsIf">PublishPreburnQueueAbortsIf</a>&lt;CoinType&gt;;
<b>include</b> <a href="Diem.md#0x1_Diem_PublishPreburnQueueEnsures">PublishPreburnQueueEnsures</a>&lt;CoinType&gt;;
</code></pre>




<a name="0x1_Diem_PublishPreburnQueueAbortsIf"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_PublishPreburnQueueAbortsIf">PublishPreburnQueueAbortsIf</a>&lt;CoinType&gt; {
    account: signer;
    <b>include</b> <a href="Roles.md#0x1_Roles_AbortsIfNotDesignatedDealer">Roles::AbortsIfNotDesignatedDealer</a>;
    <b>include</b> <a href="Diem.md#0x1_Diem_AbortsIfNoCurrency">AbortsIfNoCurrency</a>&lt;CoinType&gt;;
}
</code></pre>




<a name="0x1_Diem_PublishPreburnQueueEnsures"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_PublishPreburnQueueEnsures">PublishPreburnQueueEnsures</a>&lt;CoinType&gt; {
    account: signer;
    <b>let</b> account_addr = <a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(account);
    <b>ensures</b> <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(account_addr);
    <b>ensures</b> !<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_Preburn">Preburn</a>&lt;CoinType&gt;&gt;(account_addr);
    <b>ensures</b> <a href="../../../../../../move-stdlib/docs/Vector.md#0x1_Vector_length">Vector::length</a>(<b>global</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(account_addr).preburns) == 0;
}
</code></pre>



</details>

<a name="0x1_Diem_publish_preburn_queue_to_account"></a>

## Function `publish_preburn_queue_to_account`

Publish a <code><a href="Diem.md#0x1_Diem_Preburn">Preburn</a></code> resource under <code>account</code>. This function is
used for bootstrapping the designated dealer at account-creation
time, and the association TC account <code>tc_account</code> (at <code>@TreasuryCompliance</code>) is creating
this resource for the designated dealer <code>account</code>.


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_publish_preburn_queue_to_account">publish_preburn_queue_to_account</a>&lt;CoinType&gt;(account: &signer, tc_account: &signer)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_publish_preburn_queue_to_account">publish_preburn_queue_to_account</a>&lt;CoinType&gt;(
    account: &signer,
    tc_account: &signer
) <b>acquires</b> <a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a> {
    <a href="Roles.md#0x1_Roles_assert_designated_dealer">Roles::assert_designated_dealer</a>(account);
    <a href="Roles.md#0x1_Roles_assert_treasury_compliance">Roles::assert_treasury_compliance</a>(tc_account);
    <b>assert</b>(!<a href="Diem.md#0x1_Diem_is_synthetic_currency">is_synthetic_currency</a>&lt;CoinType&gt;(), <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_invalid_argument">Errors::invalid_argument</a>(<a href="Diem.md#0x1_Diem_EIS_SYNTHETIC_CURRENCY">EIS_SYNTHETIC_CURRENCY</a>));
    <a href="Diem.md#0x1_Diem_publish_preburn_queue">publish_preburn_queue</a>&lt;CoinType&gt;(account)
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>pragma</b> opaque;
<b>let</b> account_addr = <a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(account);
<b>modifies</b> <b>global</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(account_addr);
</code></pre>


The premission "PreburnCurrency" is granted to DesignatedDealer [[H4]][PERMISSION].
Must abort if the account does not have the DesignatedDealer role.


<pre><code><b>include</b> <a href="Roles.md#0x1_Roles_AbortsIfNotDesignatedDealer">Roles::AbortsIfNotDesignatedDealer</a>;
</code></pre>


PreburnQueue is published under the DesignatedDealer account.


<pre><code><b>include</b> <a href="Diem.md#0x1_Diem_PublishPreburnQueueAbortsIf">PublishPreburnQueueAbortsIf</a>&lt;CoinType&gt;;
<b>include</b> <a href="Diem.md#0x1_Diem_PublishPreburnQueueEnsures">PublishPreburnQueueEnsures</a>&lt;CoinType&gt;;
<b>ensures</b> <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(account_addr);
<b>include</b> <a href="Roles.md#0x1_Roles_AbortsIfNotTreasuryCompliance">Roles::AbortsIfNotTreasuryCompliance</a>{account: tc_account};
<b>include</b> <a href="Diem.md#0x1_Diem_AbortsIfNoCurrency">AbortsIfNoCurrency</a>&lt;CoinType&gt;;
<b>aborts_if</b> <a href="Diem.md#0x1_Diem_is_synthetic_currency">is_synthetic_currency</a>&lt;CoinType&gt;() <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>;
<b>aborts_if</b> <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(account_addr) <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a>;
<b>aborts_if</b> <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_Preburn">Preburn</a>&lt;CoinType&gt;&gt;(account_addr) <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_STATE">Errors::INVALID_STATE</a>;
</code></pre>



</details>

<a name="0x1_Diem_upgrade_preburn"></a>

## Function `upgrade_preburn`

Upgrade a designated dealer account from using a single <code><a href="Diem.md#0x1_Diem_Preburn">Preburn</a></code>
resource to using a <code><a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a></code> resource so that multiple preburn
requests can be outstanding in the same currency for a designated dealer.


<pre><code><b>fun</b> <a href="Diem.md#0x1_Diem_upgrade_preburn">upgrade_preburn</a>&lt;CoinType&gt;(account: &signer)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>fun</b> <a href="Diem.md#0x1_Diem_upgrade_preburn">upgrade_preburn</a>&lt;CoinType&gt;(account: &signer)
<b>acquires</b> <a href="Diem.md#0x1_Diem_Preburn">Preburn</a>, <a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a> {
    <a href="Roles.md#0x1_Roles_assert_designated_dealer">Roles::assert_designated_dealer</a>(account);
    <b>let</b> sender = <a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_address_of">Signer::address_of</a>(account);
    <b>let</b> preburn_exists = <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_Preburn">Preburn</a>&lt;CoinType&gt;&gt;(sender);
    <b>let</b> preburn_queue_exists = <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(sender);
    // The DD must already have an existing `<a href="Diem.md#0x1_Diem_Preburn">Preburn</a>` <b>resource</b>, and not a
    // `<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>` <b>resource</b> already, in order <b>to</b> be upgraded.
    <b>if</b> (preburn_exists && !preburn_queue_exists) {
        <b>let</b> <a href="Diem.md#0x1_Diem_Preburn">Preburn</a> { to_burn } = move_from&lt;<a href="Diem.md#0x1_Diem_Preburn">Preburn</a>&lt;CoinType&gt;&gt;(sender);
        <a href="Diem.md#0x1_Diem_publish_preburn_queue">publish_preburn_queue</a>&lt;CoinType&gt;(account);
        // If the DD has an <b>old</b> preburn balance, this is converted over
        // into the new preburn queue when it's upgraded.
        <b>if</b> (to_burn.value &gt; 0)  {
            <a href="Diem.md#0x1_Diem_add_preburn_to_queue">add_preburn_to_queue</a>(account, <a href="Diem.md#0x1_Diem_PreburnWithMetadata">PreburnWithMetadata</a> {
                preburn: <a href="Diem.md#0x1_Diem_Preburn">Preburn</a> { to_burn },
                metadata: x"",
            })
        } <b>else</b> {
            <a href="Diem.md#0x1_Diem_destroy_zero">destroy_zero</a>(to_burn)
        };
    }
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>let</b> account_addr = <a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(account);
<b>modifies</b> <b>global</b>&lt;<a href="Diem.md#0x1_Diem_Preburn">Preburn</a>&lt;CoinType&gt;&gt;(account_addr);
<b>modifies</b> <b>global</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(account_addr);
<b>include</b> <a href="Diem.md#0x1_Diem_UpgradePreburnAbortsIf">UpgradePreburnAbortsIf</a>&lt;CoinType&gt;;
<b>include</b> <a href="Diem.md#0x1_Diem_UpgradePreburnEnsures">UpgradePreburnEnsures</a>&lt;CoinType&gt;;
</code></pre>




<a name="0x1_Diem_UpgradePreburnAbortsIf"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_UpgradePreburnAbortsIf">UpgradePreburnAbortsIf</a>&lt;CoinType&gt; {
    account: signer;
    <b>let</b> account_addr = <a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(account);
    <b>let</b> upgrade = <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_Preburn">Preburn</a>&lt;CoinType&gt;&gt;(account_addr) && !<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(account_addr);
}
</code></pre>


Must abort if the account doesn't have the <code><a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a></code> or
<code><a href="Diem.md#0x1_Diem_Preburn">Preburn</a></code> resource to satisfy [[H4]][PERMISSION] of <code>preburn_to</code>.


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_UpgradePreburnAbortsIf">UpgradePreburnAbortsIf</a>&lt;CoinType&gt; {
    <b>include</b> upgrade ==&gt; <a href="Diem.md#0x1_Diem_PublishPreburnQueueAbortsIf">PublishPreburnQueueAbortsIf</a>&lt;CoinType&gt;;
    <b>include</b> <a href="Roles.md#0x1_Roles_AbortsIfNotDesignatedDealer">Roles::AbortsIfNotDesignatedDealer</a>;
}
</code></pre>




<a name="0x1_Diem_UpgradePreburnEnsures"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_UpgradePreburnEnsures">UpgradePreburnEnsures</a>&lt;CoinType&gt; {
    account: signer;
    <b>let</b> account_addr = <a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(account);
    <b>let</b> upgrade = <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_Preburn">Preburn</a>&lt;CoinType&gt;&gt;(account_addr) && !<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(account_addr);
    <b>let</b> preburn = <b>global</b>&lt;<a href="Diem.md#0x1_Diem_Preburn">Preburn</a>&lt;CoinType&gt;&gt;(account_addr);
    <b>ensures</b> upgrade ==&gt;
        !<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_Preburn">Preburn</a>&lt;CoinType&gt;&gt;(account_addr) && <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(account_addr);
    <b>ensures</b> upgrade && preburn.to_burn.value &gt; 0 ==&gt;
        <b>global</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(account_addr).preburns ==
            vec(<a href="Diem.md#0x1_Diem_PreburnWithMetadata">PreburnWithMetadata</a> { preburn, metadata: x"" });
    <b>ensures</b> upgrade && preburn.to_burn.value == 0 ==&gt;
        <b>global</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(account_addr).preburns == vec();
}
</code></pre>



</details>

<a name="0x1_Diem_add_preburn_to_queue"></a>

## Function `add_preburn_to_queue`

Add the <code>preburn</code> request to the preburn queue of <code>account</code>, and check that the
number of preburn requests does not exceed <code><a href="Diem.md#0x1_Diem_MAX_OUTSTANDING_PREBURNS">MAX_OUTSTANDING_PREBURNS</a></code>.


<pre><code><b>fun</b> <a href="Diem.md#0x1_Diem_add_preburn_to_queue">add_preburn_to_queue</a>&lt;CoinType&gt;(account: &signer, preburn: <a href="Diem.md#0x1_Diem_PreburnWithMetadata">Diem::PreburnWithMetadata</a>&lt;CoinType&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>fun</b> <a href="Diem.md#0x1_Diem_add_preburn_to_queue">add_preburn_to_queue</a>&lt;CoinType&gt;(account: &signer, preburn: <a href="Diem.md#0x1_Diem_PreburnWithMetadata">PreburnWithMetadata</a>&lt;CoinType&gt;)
<b>acquires</b> <a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a> {
    <b>let</b> account_addr = <a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_address_of">Signer::address_of</a>(account);
    <b>assert</b>(<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(account_addr), <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_invalid_state">Errors::invalid_state</a>(<a href="Diem.md#0x1_Diem_EPREBURN_QUEUE">EPREBURN_QUEUE</a>));
    <b>assert</b>(<a href="Diem.md#0x1_Diem_value">value</a>(&preburn.preburn.to_burn) &gt; 0, <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_invalid_argument">Errors::invalid_argument</a>(<a href="Diem.md#0x1_Diem_EPREBURN">EPREBURN</a>));
    <b>let</b> preburns = &<b>mut</b> borrow_global_mut&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(account_addr).preburns;
    <b>assert</b>(
        <a href="../../../../../../move-stdlib/docs/Vector.md#0x1_Vector_length">Vector::length</a>(preburns) &lt; <a href="Diem.md#0x1_Diem_MAX_OUTSTANDING_PREBURNS">MAX_OUTSTANDING_PREBURNS</a>,
        <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_limit_exceeded">Errors::limit_exceeded</a>(<a href="Diem.md#0x1_Diem_EPREBURN_QUEUE">EPREBURN_QUEUE</a>)
    );
    <a href="../../../../../../move-stdlib/docs/Vector.md#0x1_Vector_push_back">Vector::push_back</a>(preburns, preburn);
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>pragma</b> opaque;
<b>let</b> account_addr = <a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(account);
<b>let</b> preburns = <b>global</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(account_addr).preburns;
<b>let</b> post post_preburns = <b>global</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(account_addr).preburns;
<b>modifies</b> <b>global</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(account_addr);
<b>aborts_if</b> !<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(account_addr) <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_STATE">Errors::INVALID_STATE</a>;
<b>include</b> <a href="Diem.md#0x1_Diem_AddPreburnToQueueAbortsIf">AddPreburnToQueueAbortsIf</a>&lt;CoinType&gt;;
<b>ensures</b> <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(account_addr);
<b>ensures</b> <a href="../../../../../../move-stdlib/docs/Vector.md#0x1_Vector_eq_push_back">Vector::eq_push_back</a>(post_preburns, preburns, preburn);
</code></pre>




<a name="0x1_Diem_AddPreburnToQueueAbortsIf"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_AddPreburnToQueueAbortsIf">AddPreburnToQueueAbortsIf</a>&lt;CoinType&gt; {
    account: signer;
    preburn: <a href="Diem.md#0x1_Diem_PreburnWithMetadata">PreburnWithMetadata</a>&lt;CoinType&gt;;
    <b>let</b> account_addr = <a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(account);
    <b>aborts_if</b> preburn.preburn.to_burn.value == 0 <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>;
    <b>aborts_if</b> <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(account_addr) &&
        <a href="../../../../../../move-stdlib/docs/Vector.md#0x1_Vector_length">Vector::length</a>(<b>global</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(account_addr).preburns) &gt;= <a href="Diem.md#0x1_Diem_MAX_OUTSTANDING_PREBURNS">MAX_OUTSTANDING_PREBURNS</a>
        <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a>;
}
</code></pre>



</details>

<a name="0x1_Diem_preburn_to"></a>

## Function `preburn_to`

Sends <code>coin</code> to the preburn queue for <code>account</code>, where it will wait to either be burned
or returned to the balance of <code>account</code>.
Calls to this function will fail if:
* <code>account</code> does not have a <code><a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;</code> resource published under it; or
* the preburn queue is already at capacity (i.e., at <code><a href="Diem.md#0x1_Diem_MAX_OUTSTANDING_PREBURNS">MAX_OUTSTANDING_PREBURNS</a></code>); or
* <code>coin</code> has a <code>value</code> field of zero.


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_preburn_to">preburn_to</a>&lt;CoinType&gt;(account: &signer, coin: <a href="Diem.md#0x1_Diem_Diem">Diem::Diem</a>&lt;CoinType&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_preburn_to">preburn_to</a>&lt;CoinType&gt;(
    account: &signer,
    coin: <a href="Diem.md#0x1_Diem">Diem</a>&lt;CoinType&gt;
) <b>acquires</b> <a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>, <a href="Diem.md#0x1_Diem_Preburn">Preburn</a>, <a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a> {
    <a href="Roles.md#0x1_Roles_assert_designated_dealer">Roles::assert_designated_dealer</a>(account);
    // any coin that is preburned needs <b>to</b> have a nonzero value
    <b>assert</b>(<a href="Diem.md#0x1_Diem_value">value</a>(&coin) &gt; 0, <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_invalid_argument">Errors::invalid_argument</a>(<a href="Diem.md#0x1_Diem_ECOIN">ECOIN</a>));
    <b>let</b> sender = <a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_address_of">Signer::address_of</a>(account);
    // After an upgrade a `<a href="Diem.md#0x1_Diem_Preburn">Preburn</a>` <b>resource</b> no longer <b>exists</b> in this
    // currency, and it is replaced <b>with</b> a `<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>` <b>resource</b>
    // for the same currency.
    <a href="Diem.md#0x1_Diem_upgrade_preburn">upgrade_preburn</a>&lt;CoinType&gt;(account);

    <b>let</b> preburn = <a href="Diem.md#0x1_Diem_PreburnWithMetadata">PreburnWithMetadata</a> {
        preburn: <a href="Diem.md#0x1_Diem_Preburn">Preburn</a> { to_burn: <a href="Diem.md#0x1_Diem_zero">zero</a>&lt;CoinType&gt;() },
        metadata: x"",
    };
    <a href="Diem.md#0x1_Diem_preburn_with_resource">preburn_with_resource</a>(coin, &<b>mut</b> preburn.preburn, sender);
    <a href="Diem.md#0x1_Diem_add_preburn_to_queue">add_preburn_to_queue</a>(account, preburn);
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>pragma</b> opaque;
<b>include</b> <a href="Diem.md#0x1_Diem_PreburnToAbortsIf">PreburnToAbortsIf</a>&lt;CoinType&gt;{amount: coin.value};
<b>include</b> <a href="Diem.md#0x1_Diem_PreburnToEnsures">PreburnToEnsures</a>&lt;CoinType&gt;{amount: coin.value};
<b>let</b> account_addr = <a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(account);
<b>include</b> <a href="Diem.md#0x1_Diem_PreburnWithResourceEmits">PreburnWithResourceEmits</a>&lt;CoinType&gt;{amount: coin.value, preburn_address: account_addr};
</code></pre>




<a name="0x1_Diem_PreburnToAbortsIf"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_PreburnToAbortsIf">PreburnToAbortsIf</a>&lt;CoinType&gt; {
    account: signer;
    amount: u64;
    <b>let</b> account_addr = <a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(account);
}
</code></pre>


Must abort if the account doesn't have the PreburnQueue or Preburn resource, or has not
the correct role [[H4]][PERMISSION].


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_PreburnToAbortsIf">PreburnToAbortsIf</a>&lt;CoinType&gt; {
    <b>aborts_if</b> !(<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_Preburn">Preburn</a>&lt;CoinType&gt;&gt;(account_addr) || <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(account_addr));
    <b>include</b> <a href="Roles.md#0x1_Roles_AbortsIfNotDesignatedDealer">Roles::AbortsIfNotDesignatedDealer</a>;
    <b>include</b> <a href="Diem.md#0x1_Diem_PreburnAbortsIf">PreburnAbortsIf</a>&lt;CoinType&gt;;
    <b>include</b> <a href="Diem.md#0x1_Diem_UpgradePreburnAbortsIf">UpgradePreburnAbortsIf</a>&lt;CoinType&gt;;
    <b>include</b> <a href="Diem.md#0x1_Diem_AddPreburnToQueueAbortsIf">AddPreburnToQueueAbortsIf</a>&lt;CoinType&gt;{preburn: <a href="Diem.md#0x1_Diem_PreburnWithMetadata">PreburnWithMetadata</a>{ preburn: <a href="Diem.md#0x1_Diem_spec_make_preburn">spec_make_preburn</a>(amount), metadata: x"" } };
}
</code></pre>




<a name="0x1_Diem_PreburnToEnsures"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_PreburnToEnsures">PreburnToEnsures</a>&lt;CoinType&gt; {
    account: signer;
    amount: u64;
    <b>let</b> account_addr = <a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(account);
}
</code></pre>


Removes the preburn resource if it exists


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_PreburnToEnsures">PreburnToEnsures</a>&lt;CoinType&gt; {
    <b>modifies</b> <b>global</b>&lt;<a href="Diem.md#0x1_Diem_Preburn">Preburn</a>&lt;CoinType&gt;&gt;(account_addr);
}
</code></pre>


Publishes if it doesn't exists. Updates its state either way.


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_PreburnToEnsures">PreburnToEnsures</a>&lt;CoinType&gt; {
    <b>modifies</b> <b>global</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(account_addr);
    <b>ensures</b> <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(account_addr);
    <b>modifies</b> <b>global</b>&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>);
    <b>include</b> <a href="Diem.md#0x1_Diem_PreburnEnsures">PreburnEnsures</a>&lt;CoinType&gt;{preburn: <a href="Diem.md#0x1_Diem_spec_make_preburn">spec_make_preburn</a>(amount)};
}
</code></pre>



</details>

<a name="0x1_Diem_remove_preburn_from_queue"></a>

## Function `remove_preburn_from_queue`

Remove the oldest preburn request in the <code><a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;</code>
resource published under <code>preburn_address</code> whose value is equal to <code>amount</code>.
Calls to this function will fail if:
* <code>preburn_address</code> doesn't have a <code><a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;</code> resource published under it; or
* a preburn request with the correct value for <code>amount</code> cannot be found in the preburn queue for <code>preburn_address</code>;


<pre><code><b>fun</b> <a href="Diem.md#0x1_Diem_remove_preburn_from_queue">remove_preburn_from_queue</a>&lt;CoinType&gt;(preburn_address: address, amount: u64): <a href="Diem.md#0x1_Diem_PreburnWithMetadata">Diem::PreburnWithMetadata</a>&lt;CoinType&gt;
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>fun</b> <a href="Diem.md#0x1_Diem_remove_preburn_from_queue">remove_preburn_from_queue</a>&lt;CoinType&gt;(preburn_address: address, amount: u64): <a href="Diem.md#0x1_Diem_PreburnWithMetadata">PreburnWithMetadata</a>&lt;CoinType&gt;
<b>acquires</b> <a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a> {
    <b>assert</b>(<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(preburn_address), <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_not_published">Errors::not_published</a>(<a href="Diem.md#0x1_Diem_EPREBURN_QUEUE">EPREBURN_QUEUE</a>));
    // We search from the head of the queue
    <b>let</b> index = 0;
    <b>let</b> preburn_queue = &<b>mut</b> borrow_global_mut&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(preburn_address).preburns;
    <b>let</b> queue_length = <a href="../../../../../../move-stdlib/docs/Vector.md#0x1_Vector_length">Vector::length</a>(preburn_queue);

    <b>while</b> ({
        <b>spec</b> {
            <b>assert</b> index &lt;= queue_length;
            <b>assert</b> <b>forall</b> j in 0..index: preburn_queue[j].preburn.to_burn.value != amount;
        };
        (index &lt; queue_length)
    }) {
        <b>let</b> elem = <a href="../../../../../../move-stdlib/docs/Vector.md#0x1_Vector_borrow">Vector::borrow</a>(preburn_queue, index);
        <b>if</b> (<a href="Diem.md#0x1_Diem_value">value</a>(&elem.preburn.to_burn) == amount) {
            <b>let</b> preburn = <a href="../../../../../../move-stdlib/docs/Vector.md#0x1_Vector_remove">Vector::remove</a>(preburn_queue, index);
            // Make sure that the value is correct
            <b>return</b> preburn
        };
        index = index + 1;
    };

    <b>spec</b> {
        <b>assert</b> index == queue_length;
        <b>assert</b> <b>forall</b> j in 0..queue_length: preburn_queue[j].preburn.to_burn.value != amount;
    };

    // If we didn't <b>return</b> already, we couldn't find a preburn <b>with</b> a matching value.
    <b>abort</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_invalid_state">Errors::invalid_state</a>(<a href="Diem.md#0x1_Diem_EPREBURN_NOT_FOUND">EPREBURN_NOT_FOUND</a>)
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>pragma</b> opaque;
<b>modifies</b> <b>global</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(preburn_address);
<b>include</b> <a href="Diem.md#0x1_Diem_RemovePreburnFromQueueAbortsIf">RemovePreburnFromQueueAbortsIf</a>&lt;CoinType&gt;;
<b>include</b> <a href="Diem.md#0x1_Diem_RemovePreburnFromQueueEnsures">RemovePreburnFromQueueEnsures</a>&lt;CoinType&gt;;
<b>ensures</b> result.preburn.to_burn.value == amount;
</code></pre>




<a name="0x1_Diem_RemovePreburnFromQueueAbortsIf"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_RemovePreburnFromQueueAbortsIf">RemovePreburnFromQueueAbortsIf</a>&lt;CoinType&gt; {
    preburn_address: address;
    amount: u64;
    <b>let</b> preburn_queue = <b>global</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(preburn_address).preburns;
    <b>aborts_if</b> !<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(preburn_address) <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>;
    <b>aborts_if</b> <b>forall</b> i in 0..len(preburn_queue): preburn_queue[i].preburn.to_burn.value != amount <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_STATE">Errors::INVALID_STATE</a>;
}
</code></pre>


> TODO: See this cannot currently be expressed in the MSL.
> See https://github.com/diem/diem/issues/7615 for more information.


<a name="0x1_Diem_RemovePreburnFromQueueEnsures"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_RemovePreburnFromQueueEnsures">RemovePreburnFromQueueEnsures</a>&lt;CoinType&gt; {
    preburn_address: address;
    amount: u64;
    <b>ensures</b> <b>old</b>(<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(preburn_address)) ==&gt; <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(preburn_address);
}
</code></pre>



</details>

<a name="0x1_Diem_burn_with_capability"></a>

## Function `burn_with_capability`

Permanently removes the coins in the oldest preburn request in the
<code><a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a></code> resource under <code>preburn_address</code> that has a <code>to_burn</code>
value of <code>amount</code> and updates the market cap accordingly.
This function can only be called by the holder of a <code><a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>&lt;CoinType&gt;</code>.
Calls to this function will fail if the there is no <code><a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;</code>
resource under <code>preburn_address</code>, or, if there is no preburn request in
the preburn queue with a <code>to_burn</code> amount equal to <code>amount</code>.


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_burn_with_capability">burn_with_capability</a>&lt;CoinType&gt;(preburn_address: address, capability: &<a href="Diem.md#0x1_Diem_BurnCapability">Diem::BurnCapability</a>&lt;CoinType&gt;, amount: u64)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_burn_with_capability">burn_with_capability</a>&lt;CoinType&gt;(
    preburn_address: address,
    capability: &<a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>&lt;CoinType&gt;,
    amount: u64,
) <b>acquires</b> <a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>, <a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a> {

    // Remove the preburn request
    <b>let</b> <a href="Diem.md#0x1_Diem_PreburnWithMetadata">PreburnWithMetadata</a>{ preburn, metadata: _ } = <a href="Diem.md#0x1_Diem_remove_preburn_from_queue">remove_preburn_from_queue</a>&lt;CoinType&gt;(preburn_address, amount);

    // Burn the contained coins
    <a href="Diem.md#0x1_Diem_burn_with_resource_cap">burn_with_resource_cap</a>(&<b>mut</b> preburn, preburn_address, capability);

    <b>let</b> <a href="Diem.md#0x1_Diem_Preburn">Preburn</a> { to_burn } = preburn;
    <a href="Diem.md#0x1_Diem_destroy_zero">destroy_zero</a>(to_burn);
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="Diem.md#0x1_Diem_BurnWithResourceCapEmits">BurnWithResourceCapEmits</a>&lt;CoinType&gt;{preburn: <a href="Diem.md#0x1_Diem_spec_make_preburn">spec_make_preburn</a>(amount)};
<b>include</b> <a href="Diem.md#0x1_Diem_BurnWithCapabilityAbortsIf">BurnWithCapabilityAbortsIf</a>&lt;CoinType&gt;;
<b>include</b> <a href="Diem.md#0x1_Diem_BurnWithCapabilityEnsures">BurnWithCapabilityEnsures</a>&lt;CoinType&gt;;
</code></pre>




<a name="0x1_Diem_BurnWithCapabilityAbortsIf"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_BurnWithCapabilityAbortsIf">BurnWithCapabilityAbortsIf</a>&lt;CoinType&gt; {
    preburn_address: address;
    amount: u64;
    <b>let</b> preburn = <a href="Diem.md#0x1_Diem_spec_make_preburn">spec_make_preburn</a>&lt;CoinType&gt;(amount);
    <b>include</b> <a href="Diem.md#0x1_Diem_AbortsIfNoPreburnQueue">AbortsIfNoPreburnQueue</a>&lt;CoinType&gt;;
    <b>include</b> <a href="Diem.md#0x1_Diem_RemovePreburnFromQueueAbortsIf">RemovePreburnFromQueueAbortsIf</a>&lt;CoinType&gt;;
    <b>include</b> <a href="Diem.md#0x1_Diem_BurnWithResourceCapAbortsIf">BurnWithResourceCapAbortsIf</a>&lt;CoinType&gt;{preburn: preburn};
}
</code></pre>




<a name="0x1_Diem_BurnWithCapabilityEnsures"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_BurnWithCapabilityEnsures">BurnWithCapabilityEnsures</a>&lt;CoinType&gt; {
    preburn_address: address;
    amount: u64;
    <b>let</b> preburn = <a href="Diem.md#0x1_Diem_spec_make_preburn">spec_make_preburn</a>&lt;CoinType&gt;(amount);
    <b>include</b> <a href="Diem.md#0x1_Diem_BurnWithResourceCapEnsures">BurnWithResourceCapEnsures</a>&lt;CoinType&gt;{preburn: preburn};
    <b>include</b> <a href="Diem.md#0x1_Diem_RemovePreburnFromQueueEnsures">RemovePreburnFromQueueEnsures</a>&lt;CoinType&gt;;
}
</code></pre>



</details>

<a name="0x1_Diem_burn_with_resource_cap"></a>

## Function `burn_with_resource_cap`

Permanently removes the coins held in the <code><a href="Diem.md#0x1_Diem_Preburn">Preburn</a></code> resource (in <code>to_burn</code> field)
that was stored in a <code><a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a></code> at <code>preburn_address</code> and updates the market cap accordingly.
This function can only be called by the holder of a <code><a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>&lt;CoinType&gt;</code>.
Calls to this function will fail if the preburn <code>to_burn</code> area for <code>CoinType</code> is empty.


<pre><code><b>fun</b> <a href="Diem.md#0x1_Diem_burn_with_resource_cap">burn_with_resource_cap</a>&lt;CoinType&gt;(preburn: &<b>mut</b> <a href="Diem.md#0x1_Diem_Preburn">Diem::Preburn</a>&lt;CoinType&gt;, preburn_address: address, _capability: &<a href="Diem.md#0x1_Diem_BurnCapability">Diem::BurnCapability</a>&lt;CoinType&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>fun</b> <a href="Diem.md#0x1_Diem_burn_with_resource_cap">burn_with_resource_cap</a>&lt;CoinType&gt;(
    preburn: &<b>mut</b> <a href="Diem.md#0x1_Diem_Preburn">Preburn</a>&lt;CoinType&gt;,
    preburn_address: address,
    _capability: &<a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>&lt;CoinType&gt;
) <b>acquires</b> <a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a> {
    <b>let</b> currency_code = <a href="Diem.md#0x1_Diem_currency_code">currency_code</a>&lt;CoinType&gt;();
    // Abort <b>if</b> no coin present in preburn area
    <b>assert</b>(preburn.to_burn.value &gt; 0, <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_invalid_state">Errors::invalid_state</a>(<a href="Diem.md#0x1_Diem_EPREBURN_EMPTY">EPREBURN_EMPTY</a>));
    // destroy the coin in <a href="Diem.md#0x1_Diem_Preburn">Preburn</a> area
    <b>let</b> <a href="Diem.md#0x1_Diem">Diem</a> { value } = <a href="Diem.md#0x1_Diem_withdraw_all">withdraw_all</a>&lt;CoinType&gt;(&<b>mut</b> preburn.to_burn);
    // <b>update</b> the market cap
    <a href="Diem.md#0x1_Diem_assert_is_currency">assert_is_currency</a>&lt;CoinType&gt;();
    <b>let</b> info = borrow_global_mut&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>);
    <b>assert</b>(info.total_value &gt;= (value <b>as</b> u128), <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_limit_exceeded">Errors::limit_exceeded</a>(<a href="Diem.md#0x1_Diem_ECURRENCY_INFO">ECURRENCY_INFO</a>));
    info.total_value = info.total_value - (value <b>as</b> u128);
    <b>assert</b>(info.preburn_value &gt;= value, <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_limit_exceeded">Errors::limit_exceeded</a>(<a href="Diem.md#0x1_Diem_EPREBURN">EPREBURN</a>));
    info.preburn_value = info.preburn_value - value;
    // don't emit burn events for synthetic currenices <b>as</b> this does not
    // change the total value of fiat currencies held on-chain.
    <b>if</b> (!info.is_synthetic) {
        <a href="../../../../../../move-stdlib/docs/Event.md#0x1_Event_emit_event">Event::emit_event</a>(
            &<b>mut</b> info.burn_events,
            <a href="Diem.md#0x1_Diem_BurnEvent">BurnEvent</a> {
                amount: value,
                currency_code,
                preburn_address,
            }
        );
    };
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>let</b> pre_preburn = preburn;
<b>include</b> <a href="Diem.md#0x1_Diem_BurnWithResourceCapAbortsIf">BurnWithResourceCapAbortsIf</a>&lt;CoinType&gt;{preburn: pre_preburn};
<b>include</b> <a href="Diem.md#0x1_Diem_BurnWithResourceCapEnsures">BurnWithResourceCapEnsures</a>&lt;CoinType&gt;{preburn: pre_preburn};
<b>include</b> <a href="Diem.md#0x1_Diem_BurnWithResourceCapEmits">BurnWithResourceCapEmits</a>&lt;CoinType&gt;{preburn: pre_preburn};
</code></pre>




<a name="0x1_Diem_BurnWithResourceCapAbortsIf"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_BurnWithResourceCapAbortsIf">BurnWithResourceCapAbortsIf</a>&lt;CoinType&gt; {
    preburn: <a href="Diem.md#0x1_Diem_Preburn">Preburn</a>&lt;CoinType&gt;;
    <b>include</b> <a href="Diem.md#0x1_Diem_AbortsIfNoCurrency">AbortsIfNoCurrency</a>&lt;CoinType&gt;;
    <b>let</b> to_burn = preburn.to_burn.value;
    <b>let</b> info = <a href="Diem.md#0x1_Diem_spec_currency_info">spec_currency_info</a>&lt;CoinType&gt;();
    <b>aborts_if</b> to_burn == 0 <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_STATE">Errors::INVALID_STATE</a>;
    <b>aborts_if</b> info.total_value &lt; to_burn <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a>;
    <b>aborts_if</b> info.<a href="Diem.md#0x1_Diem_preburn_value">preburn_value</a> &lt; to_burn <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a>;
}
</code></pre>




<a name="0x1_Diem_BurnWithResourceCapEnsures"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_BurnWithResourceCapEnsures">BurnWithResourceCapEnsures</a>&lt;CoinType&gt; {
    preburn: <a href="Diem.md#0x1_Diem_Preburn">Preburn</a>&lt;CoinType&gt;;
    <b>ensures</b> <a href="Diem.md#0x1_Diem_spec_currency_info">spec_currency_info</a>&lt;CoinType&gt;().total_value
            == <b>old</b>(<a href="Diem.md#0x1_Diem_spec_currency_info">spec_currency_info</a>&lt;CoinType&gt;().total_value) - preburn.to_burn.value;
    <b>ensures</b> <a href="Diem.md#0x1_Diem_spec_currency_info">spec_currency_info</a>&lt;CoinType&gt;().preburn_value
            == <b>old</b>(<a href="Diem.md#0x1_Diem_spec_currency_info">spec_currency_info</a>&lt;CoinType&gt;().preburn_value) - preburn.to_burn.value;
}
</code></pre>




<a name="0x1_Diem_BurnWithResourceCapEmits"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_BurnWithResourceCapEmits">BurnWithResourceCapEmits</a>&lt;CoinType&gt; {
    preburn: <a href="Diem.md#0x1_Diem_Preburn">Preburn</a>&lt;CoinType&gt;;
    preburn_address: address;
    <b>let</b> info = <a href="Diem.md#0x1_Diem_spec_currency_info">spec_currency_info</a>&lt;CoinType&gt;();
    <b>let</b> currency_code = <a href="Diem.md#0x1_Diem_spec_currency_code">spec_currency_code</a>&lt;CoinType&gt;();
    <b>let</b> handle = info.burn_events;
    emits <a href="Diem.md#0x1_Diem_BurnEvent">BurnEvent</a> {
            amount: preburn.to_burn.value,
            currency_code,
            preburn_address,
        }
        <b>to</b> handle <b>if</b> !info.is_synthetic;
}
</code></pre>



</details>

<a name="0x1_Diem_cancel_burn_with_capability"></a>

## Function `cancel_burn_with_capability`

Cancels the oldest preburn request held in the <code><a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a></code> resource under
<code>preburn_address</code> with a <code>to_burn</code> amount matching <code>amount</code>. It then returns these coins to the caller.
This function can only be called by the holder of a
<code><a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>&lt;CoinType&gt;</code>, and will fail if the <code><a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;</code> resource
at <code>preburn_address</code> does not contain a preburn request of the right amount.


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_cancel_burn_with_capability">cancel_burn_with_capability</a>&lt;CoinType&gt;(preburn_address: address, _capability: &<a href="Diem.md#0x1_Diem_BurnCapability">Diem::BurnCapability</a>&lt;CoinType&gt;, amount: u64): <a href="Diem.md#0x1_Diem_Diem">Diem::Diem</a>&lt;CoinType&gt;
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_cancel_burn_with_capability">cancel_burn_with_capability</a>&lt;CoinType&gt;(
    preburn_address: address,
    _capability: &<a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>&lt;CoinType&gt;,
    amount: u64,
): <a href="Diem.md#0x1_Diem">Diem</a>&lt;CoinType&gt; <b>acquires</b> <a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>, <a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a> {

    // destroy the coin in the preburn area
    <b>let</b> <a href="Diem.md#0x1_Diem_PreburnWithMetadata">PreburnWithMetadata</a>{ preburn: <a href="Diem.md#0x1_Diem_Preburn">Preburn</a> { to_burn }, metadata: _ } = <a href="Diem.md#0x1_Diem_remove_preburn_from_queue">remove_preburn_from_queue</a>&lt;CoinType&gt;(preburn_address, amount);

    // <b>update</b> the market cap
    <b>let</b> currency_code = <a href="Diem.md#0x1_Diem_currency_code">currency_code</a>&lt;CoinType&gt;();
    <b>let</b> info = borrow_global_mut&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>);
    <b>assert</b>(info.preburn_value &gt;= amount, <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_limit_exceeded">Errors::limit_exceeded</a>(<a href="Diem.md#0x1_Diem_EPREBURN">EPREBURN</a>));
    info.preburn_value = info.preburn_value - amount;
    // Don't emit cancel burn events for synthetic currencies. cancel_burn
    // shouldn't be be used for synthetic coins in the first place.
    <b>if</b> (!info.is_synthetic) {
        <a href="../../../../../../move-stdlib/docs/Event.md#0x1_Event_emit_event">Event::emit_event</a>(
            &<b>mut</b> info.cancel_burn_events,
            <a href="Diem.md#0x1_Diem_CancelBurnEvent">CancelBurnEvent</a> {
                amount,
                currency_code,
                preburn_address,
            }
        );
    };

    to_burn
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>modifies</b> <b>global</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(preburn_address);
<b>modifies</b> <b>global</b>&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>);
<b>include</b> <a href="Diem.md#0x1_Diem_CancelBurnWithCapAbortsIf">CancelBurnWithCapAbortsIf</a>&lt;CoinType&gt;;
<b>include</b> <a href="Diem.md#0x1_Diem_CancelBurnWithCapEnsures">CancelBurnWithCapEnsures</a>&lt;CoinType&gt;;
<b>include</b> <a href="Diem.md#0x1_Diem_CancelBurnWithCapEmits">CancelBurnWithCapEmits</a>&lt;CoinType&gt;;
<b>ensures</b> <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>);
<b>ensures</b> result.value == amount;
<b>ensures</b> result.value &gt; 0;
</code></pre>




<a name="0x1_Diem_CancelBurnWithCapAbortsIf"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_CancelBurnWithCapAbortsIf">CancelBurnWithCapAbortsIf</a>&lt;CoinType&gt; {
    preburn_address: address;
    amount: u64;
    <b>let</b> info = <b>global</b>&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>);
    <b>include</b> <a href="Diem.md#0x1_Diem_AbortsIfNoCurrency">AbortsIfNoCurrency</a>&lt;CoinType&gt;;
    <b>include</b> <a href="Diem.md#0x1_Diem_RemovePreburnFromQueueAbortsIf">RemovePreburnFromQueueAbortsIf</a>&lt;CoinType&gt;;
    <b>aborts_if</b> info.<a href="Diem.md#0x1_Diem_preburn_value">preburn_value</a> &lt; amount <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a>;
}
</code></pre>




<a name="0x1_Diem_CancelBurnWithCapEnsures"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_CancelBurnWithCapEnsures">CancelBurnWithCapEnsures</a>&lt;CoinType&gt; {
    preburn_address: address;
    amount: u64;
    <b>include</b> <a href="Diem.md#0x1_Diem_RemovePreburnFromQueueEnsures">RemovePreburnFromQueueEnsures</a>&lt;CoinType&gt;;
    <b>let</b> info = <b>global</b>&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>);
    <b>let</b> post post_info = <b>global</b>&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>);
    <b>ensures</b> post_info == update_field(info, preburn_value, info.preburn_value - amount);
}
</code></pre>




<a name="0x1_Diem_CancelBurnWithCapEmits"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_CancelBurnWithCapEmits">CancelBurnWithCapEmits</a>&lt;CoinType&gt; {
    preburn_address: address;
    amount: u64;
    <b>let</b> info = <a href="Diem.md#0x1_Diem_spec_currency_info">spec_currency_info</a>&lt;CoinType&gt;();
    <b>let</b> currency_code = <a href="Diem.md#0x1_Diem_spec_currency_code">spec_currency_code</a>&lt;CoinType&gt;();
    <b>let</b> handle = info.cancel_burn_events;
    emits <a href="Diem.md#0x1_Diem_CancelBurnEvent">CancelBurnEvent</a> {
           amount,
           currency_code,
           preburn_address,
       }
       <b>to</b> handle <b>if</b> !info.is_synthetic;
}
</code></pre>



</details>

<a name="0x1_Diem_burn_now"></a>

## Function `burn_now`

A shortcut for immediately burning a coin. This calls preburn followed by a subsequent burn, and is
used for administrative burns, like unpacking an XDX coin or charging fees.


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_burn_now">burn_now</a>&lt;CoinType&gt;(coin: <a href="Diem.md#0x1_Diem_Diem">Diem::Diem</a>&lt;CoinType&gt;, preburn: &<b>mut</b> <a href="Diem.md#0x1_Diem_Preburn">Diem::Preburn</a>&lt;CoinType&gt;, preburn_address: address, capability: &<a href="Diem.md#0x1_Diem_BurnCapability">Diem::BurnCapability</a>&lt;CoinType&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_burn_now">burn_now</a>&lt;CoinType&gt;(
    coin: <a href="Diem.md#0x1_Diem">Diem</a>&lt;CoinType&gt;,
    preburn: &<b>mut</b> <a href="Diem.md#0x1_Diem_Preburn">Preburn</a>&lt;CoinType&gt;,
    preburn_address: address,
    capability: &<a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>&lt;CoinType&gt;
) <b>acquires</b> <a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a> {
    <b>assert</b>(coin.value &gt; 0, <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_invalid_argument">Errors::invalid_argument</a>(<a href="Diem.md#0x1_Diem_ECOIN">ECOIN</a>));
    <a href="Diem.md#0x1_Diem_preburn_with_resource">preburn_with_resource</a>(coin, preburn, preburn_address);
    <a href="Diem.md#0x1_Diem_burn_with_resource_cap">burn_with_resource_cap</a>(preburn, preburn_address, capability);
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="Diem.md#0x1_Diem_BurnNowAbortsIf">BurnNowAbortsIf</a>&lt;CoinType&gt;;
<b>let</b> info = <a href="Diem.md#0x1_Diem_spec_currency_info">spec_currency_info</a>&lt;CoinType&gt;();
<b>let</b> post post_info = <a href="Diem.md#0x1_Diem_spec_currency_info">spec_currency_info</a>&lt;CoinType&gt;();
<b>include</b> <a href="Diem.md#0x1_Diem_PreburnWithResourceEmits">PreburnWithResourceEmits</a>&lt;CoinType&gt;{amount: coin.value, preburn_address: preburn_address};
<b>include</b> <a href="Diem.md#0x1_Diem_BurnWithResourceCapEmits">BurnWithResourceCapEmits</a>&lt;CoinType&gt;{preburn: <a href="Diem.md#0x1_Diem_Preburn">Preburn</a>&lt;CoinType&gt;{to_burn: coin}};
<b>ensures</b> preburn.to_burn.value == 0;
<b>ensures</b> post_info == update_field(info, total_value, info.total_value - coin.value);
</code></pre>




<a name="0x1_Diem_BurnNowAbortsIf"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_BurnNowAbortsIf">BurnNowAbortsIf</a>&lt;CoinType&gt; {
    coin: <a href="Diem.md#0x1_Diem">Diem</a>&lt;CoinType&gt;;
    preburn: <a href="Diem.md#0x1_Diem_Preburn">Preburn</a>&lt;CoinType&gt;;
    <b>aborts_if</b> coin.value == 0 <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>;
    <b>include</b> <a href="Diem.md#0x1_Diem_PreburnWithResourceAbortsIf">PreburnWithResourceAbortsIf</a>&lt;CoinType&gt;{amount: coin.value};
    <b>let</b> info = <a href="Diem.md#0x1_Diem_spec_currency_info">spec_currency_info</a>&lt;CoinType&gt;();
    <b>aborts_if</b> info.total_value &lt; coin.value <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a>;
}
</code></pre>



</details>

<a name="0x1_Diem_remove_burn_capability"></a>

## Function `remove_burn_capability`

Removes and returns the <code><a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>&lt;CoinType&gt;</code> from <code>account</code>.
Calls to this function will fail if <code>account</code> does  not have a
published <code><a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>&lt;CoinType&gt;</code> resource at the top-level.


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_remove_burn_capability">remove_burn_capability</a>&lt;CoinType&gt;(account: &signer): <a href="Diem.md#0x1_Diem_BurnCapability">Diem::BurnCapability</a>&lt;CoinType&gt;
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_remove_burn_capability">remove_burn_capability</a>&lt;CoinType&gt;(account: &signer): <a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>&lt;CoinType&gt;
<b>acquires</b> <a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a> {
    <b>let</b> addr = <a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_address_of">Signer::address_of</a>(account);
    <b>assert</b>(<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>&lt;CoinType&gt;&gt;(addr), <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_requires_capability">Errors::requires_capability</a>(<a href="Diem.md#0x1_Diem_EBURN_CAPABILITY">EBURN_CAPABILITY</a>));
    move_from&lt;<a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>&lt;CoinType&gt;&gt;(addr)
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="Diem.md#0x1_Diem_AbortsIfNoBurnCapability">AbortsIfNoBurnCapability</a>&lt;CoinType&gt;;
</code></pre>




<a name="0x1_Diem_AbortsIfNoBurnCapability"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_AbortsIfNoBurnCapability">AbortsIfNoBurnCapability</a>&lt;CoinType&gt; {
    account: signer;
    <b>aborts_if</b> !<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>&lt;CoinType&gt;&gt;(<a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(account)) <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_CAPABILITY">Errors::REQUIRES_CAPABILITY</a>;
}
</code></pre>



</details>

<a name="0x1_Diem_preburn_value"></a>

## Function `preburn_value`

Returns the total value of <code><a href="Diem.md#0x1_Diem">Diem</a>&lt;CoinType&gt;</code> that is waiting to be
burned throughout the system (i.e. the sum of all outstanding
preburn requests across all preburn resources for the <code>CoinType</code>
currency).


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_preburn_value">preburn_value</a>&lt;CoinType&gt;(): u64
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_preburn_value">preburn_value</a>&lt;CoinType&gt;(): u64 <b>acquires</b> <a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a> {
    <a href="Diem.md#0x1_Diem_assert_is_currency">assert_is_currency</a>&lt;CoinType&gt;();
    borrow_global&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>).preburn_value
}
</code></pre>



</details>

<a name="0x1_Diem_zero"></a>

## Function `zero`

Create a new <code><a href="Diem.md#0x1_Diem">Diem</a>&lt;CoinType&gt;</code> with a value of <code>0</code>. Anyone can call
this and it will be successful as long as <code>CoinType</code> is a registered currency.


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_zero">zero</a>&lt;CoinType&gt;(): <a href="Diem.md#0x1_Diem_Diem">Diem::Diem</a>&lt;CoinType&gt;
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_zero">zero</a>&lt;CoinType&gt;(): <a href="Diem.md#0x1_Diem">Diem</a>&lt;CoinType&gt; {
    <a href="Diem.md#0x1_Diem_assert_is_currency">assert_is_currency</a>&lt;CoinType&gt;();
    <a href="Diem.md#0x1_Diem">Diem</a>&lt;CoinType&gt; { value: 0 }
}
</code></pre>



</details>

<a name="0x1_Diem_value"></a>

## Function `value`

Returns the <code>value</code> of the passed in <code>coin</code>. The value is
represented in the base units for the currency represented by
<code>CoinType</code>.


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_value">value</a>&lt;CoinType&gt;(coin: &<a href="Diem.md#0x1_Diem_Diem">Diem::Diem</a>&lt;CoinType&gt;): u64
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_value">value</a>&lt;CoinType&gt;(coin: &<a href="Diem.md#0x1_Diem">Diem</a>&lt;CoinType&gt;): u64 {
    coin.value
}
</code></pre>



</details>

<a name="0x1_Diem_split"></a>

## Function `split`

Removes <code>amount</code> of value from the passed in <code>coin</code>. Returns the
remaining balance of the passed in <code>coin</code>, along with another coin
with value equal to <code>amount</code>. Calls will fail if <code>amount &gt; <a href="Diem.md#0x1_Diem_value">Diem::value</a>(&coin)</code>.


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_split">split</a>&lt;CoinType&gt;(coin: <a href="Diem.md#0x1_Diem_Diem">Diem::Diem</a>&lt;CoinType&gt;, amount: u64): (<a href="Diem.md#0x1_Diem_Diem">Diem::Diem</a>&lt;CoinType&gt;, <a href="Diem.md#0x1_Diem_Diem">Diem::Diem</a>&lt;CoinType&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_split">split</a>&lt;CoinType&gt;(coin: <a href="Diem.md#0x1_Diem">Diem</a>&lt;CoinType&gt;, amount: u64): (<a href="Diem.md#0x1_Diem">Diem</a>&lt;CoinType&gt;, <a href="Diem.md#0x1_Diem">Diem</a>&lt;CoinType&gt;) {
    <b>let</b> other = <a href="Diem.md#0x1_Diem_withdraw">withdraw</a>(&<b>mut</b> coin, amount);
    (coin, other)
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>aborts_if</b> coin.<a href="Diem.md#0x1_Diem_value">value</a> &lt; amount <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a>;
<b>ensures</b> result_1.value == coin.value - amount;
<b>ensures</b> result_2.value == amount;
</code></pre>



</details>

<a name="0x1_Diem_withdraw"></a>

## Function `withdraw`

Withdraw <code>amount</code> from the passed-in <code>coin</code>, where the original coin is modified in place.
After this function is executed, the original <code>coin</code> will have
<code>value = original_value - amount</code>, and the new coin will have a <code>value = amount</code>.
Calls will abort if the passed-in <code>amount</code> is greater than the
value of the passed-in <code>coin</code>.


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_withdraw">withdraw</a>&lt;CoinType&gt;(coin: &<b>mut</b> <a href="Diem.md#0x1_Diem_Diem">Diem::Diem</a>&lt;CoinType&gt;, amount: u64): <a href="Diem.md#0x1_Diem_Diem">Diem::Diem</a>&lt;CoinType&gt;
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_withdraw">withdraw</a>&lt;CoinType&gt;(coin: &<b>mut</b> <a href="Diem.md#0x1_Diem">Diem</a>&lt;CoinType&gt;, amount: u64): <a href="Diem.md#0x1_Diem">Diem</a>&lt;CoinType&gt; {
    // Check that `amount` is less than the coin's value
    <b>assert</b>(coin.value &gt;= amount, <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_limit_exceeded">Errors::limit_exceeded</a>(<a href="Diem.md#0x1_Diem_EAMOUNT_EXCEEDS_COIN_VALUE">EAMOUNT_EXCEEDS_COIN_VALUE</a>));
    coin.value = coin.value - amount;
    <a href="Diem.md#0x1_Diem">Diem</a> { value: amount }
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>pragma</b> opaque;
<b>include</b> <a href="Diem.md#0x1_Diem_WithdrawAbortsIf">WithdrawAbortsIf</a>&lt;CoinType&gt;;
<b>ensures</b> coin.value == <b>old</b>(coin.value) - amount;
<b>ensures</b> result.value == amount;
</code></pre>




<a name="0x1_Diem_WithdrawAbortsIf"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_WithdrawAbortsIf">WithdrawAbortsIf</a>&lt;CoinType&gt; {
    coin: <a href="Diem.md#0x1_Diem">Diem</a>&lt;CoinType&gt;;
    amount: u64;
    <b>aborts_if</b> coin.<a href="Diem.md#0x1_Diem_value">value</a> &lt; amount <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a>;
}
</code></pre>



</details>

<a name="0x1_Diem_withdraw_all"></a>

## Function `withdraw_all`

Return a <code><a href="Diem.md#0x1_Diem">Diem</a>&lt;CoinType&gt;</code> worth <code>coin.value</code> and reduces the <code>value</code> of the input <code>coin</code> to
zero. Does not abort.


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_withdraw_all">withdraw_all</a>&lt;CoinType&gt;(coin: &<b>mut</b> <a href="Diem.md#0x1_Diem_Diem">Diem::Diem</a>&lt;CoinType&gt;): <a href="Diem.md#0x1_Diem_Diem">Diem::Diem</a>&lt;CoinType&gt;
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_withdraw_all">withdraw_all</a>&lt;CoinType&gt;(coin: &<b>mut</b> <a href="Diem.md#0x1_Diem">Diem</a>&lt;CoinType&gt;): <a href="Diem.md#0x1_Diem">Diem</a>&lt;CoinType&gt; {
    <b>let</b> val = coin.value;
    <a href="Diem.md#0x1_Diem_withdraw">withdraw</a>(coin, val)
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>pragma</b> opaque;
<b>aborts_if</b> <b>false</b>;
<b>ensures</b> result.value == <b>old</b>(coin.value);
<b>ensures</b> coin.value == 0;
</code></pre>



</details>

<a name="0x1_Diem_join"></a>

## Function `join`

Takes two coins as input, returns a single coin with the total value of both coins.
Destroys on of the input coins.


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_join">join</a>&lt;CoinType&gt;(coin1: <a href="Diem.md#0x1_Diem_Diem">Diem::Diem</a>&lt;CoinType&gt;, coin2: <a href="Diem.md#0x1_Diem_Diem">Diem::Diem</a>&lt;CoinType&gt;): <a href="Diem.md#0x1_Diem_Diem">Diem::Diem</a>&lt;CoinType&gt;
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_join">join</a>&lt;CoinType&gt;(coin1: <a href="Diem.md#0x1_Diem">Diem</a>&lt;CoinType&gt;, coin2: <a href="Diem.md#0x1_Diem">Diem</a>&lt;CoinType&gt;): <a href="Diem.md#0x1_Diem">Diem</a>&lt;CoinType&gt;  {
    <a href="Diem.md#0x1_Diem_deposit">deposit</a>(&<b>mut</b> coin1, coin2);
    coin1
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>pragma</b> opaque;
<b>aborts_if</b> coin1.value + coin2.value &gt; max_u64() <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a>;
<b>ensures</b> result.value == coin1.value + coin2.value;
</code></pre>



</details>

<a name="0x1_Diem_deposit"></a>

## Function `deposit`

"Merges" the two coins.
The coin passed in by reference will have a value equal to the sum of the two coins
The <code>check</code> coin is consumed in the process


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_deposit">deposit</a>&lt;CoinType&gt;(coin: &<b>mut</b> <a href="Diem.md#0x1_Diem_Diem">Diem::Diem</a>&lt;CoinType&gt;, check: <a href="Diem.md#0x1_Diem_Diem">Diem::Diem</a>&lt;CoinType&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_deposit">deposit</a>&lt;CoinType&gt;(coin: &<b>mut</b> <a href="Diem.md#0x1_Diem">Diem</a>&lt;CoinType&gt;, check: <a href="Diem.md#0x1_Diem">Diem</a>&lt;CoinType&gt;) {
    <b>let</b> <a href="Diem.md#0x1_Diem">Diem</a> { value } = check;
    <b>assert</b>(<a href="Diem.md#0x1_Diem_MAX_U64">MAX_U64</a> - coin.value &gt;= value, <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_limit_exceeded">Errors::limit_exceeded</a>(<a href="Diem.md#0x1_Diem_ECOIN">ECOIN</a>));
    coin.value = coin.value + value;
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>pragma</b> opaque;
<b>include</b> <a href="Diem.md#0x1_Diem_DepositAbortsIf">DepositAbortsIf</a>&lt;CoinType&gt;;
<b>ensures</b> coin.value == <b>old</b>(coin.value) + check.value;
</code></pre>




<a name="0x1_Diem_DepositAbortsIf"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_DepositAbortsIf">DepositAbortsIf</a>&lt;CoinType&gt; {
    coin: <a href="Diem.md#0x1_Diem">Diem</a>&lt;CoinType&gt;;
    check: <a href="Diem.md#0x1_Diem">Diem</a>&lt;CoinType&gt;;
    <b>aborts_if</b> coin.value + check.value &gt; <a href="Diem.md#0x1_Diem_MAX_U64">MAX_U64</a> <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a>;
}
</code></pre>



</details>

<a name="0x1_Diem_destroy_zero"></a>

## Function `destroy_zero`

Destroy a zero-value coin. Calls will fail if the <code>value</code> in the passed-in <code>coin</code> is non-zero
so it is impossible to "burn" any non-zero amount of <code><a href="Diem.md#0x1_Diem">Diem</a></code> without having
a <code><a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a></code> for the specific <code>CoinType</code>.


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_destroy_zero">destroy_zero</a>&lt;CoinType&gt;(coin: <a href="Diem.md#0x1_Diem_Diem">Diem::Diem</a>&lt;CoinType&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_destroy_zero">destroy_zero</a>&lt;CoinType&gt;(coin: <a href="Diem.md#0x1_Diem">Diem</a>&lt;CoinType&gt;) {
    <b>let</b> <a href="Diem.md#0x1_Diem">Diem</a> { value } = coin;
    <b>assert</b>(value == 0, <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_invalid_argument">Errors::invalid_argument</a>(<a href="Diem.md#0x1_Diem_EDESTRUCTION_OF_NONZERO_COIN">EDESTRUCTION_OF_NONZERO_COIN</a>))
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>pragma</b> opaque;
<b>aborts_if</b> coin.value &gt; 0 <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>;
</code></pre>



</details>

<a name="0x1_Diem_register_currency"></a>

## Function `register_currency`

Register the type <code>CoinType</code> as a currency. Until the type is
registered as a currency it cannot be used as a coin/currency unit in Diem.
The passed-in <code>dr_account</code> must be a specific address (<code>@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a></code>) and
<code>dr_account</code> must also have the correct <code>DiemRoot</code> account role.
After the first registration of <code>CoinType</code> as a
currency, additional attempts to register <code>CoinType</code> as a currency
will abort.
When the <code>CoinType</code> is registered it publishes the
<code><a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;</code> resource under the <code>@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a></code> and
adds the currency to the set of <code><a href="RegisteredCurrencies.md#0x1_RegisteredCurrencies">RegisteredCurrencies</a></code>. It returns
<code><a href="Diem.md#0x1_Diem_MintCapability">MintCapability</a>&lt;CoinType&gt;</code> and <code><a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>&lt;CoinType&gt;</code> resources.


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_register_currency">register_currency</a>&lt;CoinType&gt;(dr_account: &signer, to_xdx_exchange_rate: <a href="../../../../../../move-stdlib/docs/FixedPoint32.md#0x1_FixedPoint32_FixedPoint32">FixedPoint32::FixedPoint32</a>, is_synthetic: bool, scaling_factor: u64, fractional_part: u64, currency_code: vector&lt;u8&gt;): (<a href="Diem.md#0x1_Diem_MintCapability">Diem::MintCapability</a>&lt;CoinType&gt;, <a href="Diem.md#0x1_Diem_BurnCapability">Diem::BurnCapability</a>&lt;CoinType&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_register_currency">register_currency</a>&lt;CoinType&gt;(
    dr_account: &signer,
    to_xdx_exchange_rate: <a href="../../../../../../move-stdlib/docs/FixedPoint32.md#0x1_FixedPoint32">FixedPoint32</a>,
    is_synthetic: bool,
    scaling_factor: u64,
    fractional_part: u64,
    currency_code: vector&lt;u8&gt;,
): (<a href="Diem.md#0x1_Diem_MintCapability">MintCapability</a>&lt;CoinType&gt;, <a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>&lt;CoinType&gt;)
{
    <a href="Roles.md#0x1_Roles_assert_diem_root">Roles::assert_diem_root</a>(dr_account);
    // Operational constraint that it must be stored under a specific address.
    <a href="CoreAddresses.md#0x1_CoreAddresses_assert_currency_info">CoreAddresses::assert_currency_info</a>(dr_account);
    <b>assert</b>(
        !<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(<a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_address_of">Signer::address_of</a>(dr_account)),
        <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_already_published">Errors::already_published</a>(<a href="Diem.md#0x1_Diem_ECURRENCY_INFO">ECURRENCY_INFO</a>)
    );
    <b>assert</b>(0 &lt; scaling_factor && <a href="Diem.md#0x1_Diem_scaling_factor">scaling_factor</a> &lt;= <a href="Diem.md#0x1_Diem_MAX_SCALING_FACTOR">MAX_SCALING_FACTOR</a>, <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_invalid_argument">Errors::invalid_argument</a>(<a href="Diem.md#0x1_Diem_ECURRENCY_INFO">ECURRENCY_INFO</a>));
    move_to(dr_account, <a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt; {
        total_value: 0,
        preburn_value: 0,
        to_xdx_exchange_rate,
        is_synthetic,
        scaling_factor,
        fractional_part,
        currency_code: <b>copy</b> currency_code,
        can_mint: <b>true</b>,
        mint_events: <a href="../../../../../../move-stdlib/docs/Event.md#0x1_Event_new_event_handle">Event::new_event_handle</a>&lt;<a href="Diem.md#0x1_Diem_MintEvent">MintEvent</a>&gt;(dr_account),
        burn_events: <a href="../../../../../../move-stdlib/docs/Event.md#0x1_Event_new_event_handle">Event::new_event_handle</a>&lt;<a href="Diem.md#0x1_Diem_BurnEvent">BurnEvent</a>&gt;(dr_account),
        preburn_events: <a href="../../../../../../move-stdlib/docs/Event.md#0x1_Event_new_event_handle">Event::new_event_handle</a>&lt;<a href="Diem.md#0x1_Diem_PreburnEvent">PreburnEvent</a>&gt;(dr_account),
        cancel_burn_events: <a href="../../../../../../move-stdlib/docs/Event.md#0x1_Event_new_event_handle">Event::new_event_handle</a>&lt;<a href="Diem.md#0x1_Diem_CancelBurnEvent">CancelBurnEvent</a>&gt;(dr_account),
        exchange_rate_update_events: <a href="../../../../../../move-stdlib/docs/Event.md#0x1_Event_new_event_handle">Event::new_event_handle</a>&lt;<a href="Diem.md#0x1_Diem_ToXDXExchangeRateUpdateEvent">ToXDXExchangeRateUpdateEvent</a>&gt;(dr_account)
    });
    <a href="RegisteredCurrencies.md#0x1_RegisteredCurrencies_add_currency_code">RegisteredCurrencies::add_currency_code</a>(
        dr_account,
        currency_code,
    );
    (<a href="Diem.md#0x1_Diem_MintCapability">MintCapability</a>&lt;CoinType&gt;{}, <a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>&lt;CoinType&gt;{})
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="Diem.md#0x1_Diem_RegisterCurrencyAbortsIf">RegisterCurrencyAbortsIf</a>&lt;CoinType&gt;;
<b>include</b> <a href="Diem.md#0x1_Diem_RegisterCurrencyEnsures">RegisterCurrencyEnsures</a>&lt;CoinType&gt;;
</code></pre>




<a name="0x1_Diem_RegisterCurrencyAbortsIf"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_RegisterCurrencyAbortsIf">RegisterCurrencyAbortsIf</a>&lt;CoinType&gt; {
    dr_account: signer;
    currency_code: vector&lt;u8&gt;;
    scaling_factor: u64;
}
</code></pre>


Must abort if the signer does not have the DiemRoot role [[H8]][PERMISSION].


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_RegisterCurrencyAbortsIf">RegisterCurrencyAbortsIf</a>&lt;CoinType&gt; {
    <b>include</b> <a href="Roles.md#0x1_Roles_AbortsIfNotDiemRoot">Roles::AbortsIfNotDiemRoot</a>{account: dr_account};
    <b>aborts_if</b> scaling_factor == 0 || scaling_factor &gt; <a href="Diem.md#0x1_Diem_MAX_SCALING_FACTOR">MAX_SCALING_FACTOR</a> <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>;
    <b>include</b> <a href="CoreAddresses.md#0x1_CoreAddresses_AbortsIfNotCurrencyInfo">CoreAddresses::AbortsIfNotCurrencyInfo</a>{account: dr_account};
    <b>aborts_if</b> <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(<a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(dr_account))
        <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a>;
    <b>include</b> <a href="RegisteredCurrencies.md#0x1_RegisteredCurrencies_AddCurrencyCodeAbortsIf">RegisteredCurrencies::AddCurrencyCodeAbortsIf</a>;
}
</code></pre>




<a name="0x1_Diem_RegisterCurrencyEnsures"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_RegisterCurrencyEnsures">RegisterCurrencyEnsures</a>&lt;CoinType&gt; {
    <b>ensures</b> <a href="Diem.md#0x1_Diem_spec_is_currency">spec_is_currency</a>&lt;CoinType&gt;();
    <b>ensures</b> <a href="Diem.md#0x1_Diem_spec_currency_info">spec_currency_info</a>&lt;CoinType&gt;().total_value == 0;
}
</code></pre>



</details>

<a name="0x1_Diem_register_SCS_currency"></a>

## Function `register_SCS_currency`

Registers a stable currency (SCS) coin -- i.e., a non-synthetic currency.
Resources are published on two distinct
accounts: The <code>CoinInfo</code> is published on the Diem root account, and the mint and
burn capabilities are published on a treasury compliance account.
This code allows different currencies to have different treasury compliance
accounts.


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_register_SCS_currency">register_SCS_currency</a>&lt;CoinType&gt;(dr_account: &signer, tc_account: &signer, to_xdx_exchange_rate: <a href="../../../../../../move-stdlib/docs/FixedPoint32.md#0x1_FixedPoint32_FixedPoint32">FixedPoint32::FixedPoint32</a>, scaling_factor: u64, fractional_part: u64, currency_code: vector&lt;u8&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_register_SCS_currency">register_SCS_currency</a>&lt;CoinType&gt;(
    dr_account: &signer,
    tc_account: &signer,
    to_xdx_exchange_rate: <a href="../../../../../../move-stdlib/docs/FixedPoint32.md#0x1_FixedPoint32">FixedPoint32</a>,
    scaling_factor: u64,
    fractional_part: u64,
    currency_code: vector&lt;u8&gt;,
) {
    <a href="Roles.md#0x1_Roles_assert_treasury_compliance">Roles::assert_treasury_compliance</a>(tc_account);
    <a href="Roles.md#0x1_Roles_assert_diem_root">Roles::assert_diem_root</a>(dr_account);
    <b>let</b> (mint_cap, burn_cap) =
        <a href="Diem.md#0x1_Diem_register_currency">register_currency</a>&lt;CoinType&gt;(
            dr_account,
            to_xdx_exchange_rate,
            <b>false</b>,   // is_synthetic
            scaling_factor,
            fractional_part,
            currency_code,
        );
    <b>assert</b>(
        !<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_MintCapability">MintCapability</a>&lt;CoinType&gt;&gt;(<a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_address_of">Signer::address_of</a>(tc_account)),
        <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_already_published">Errors::already_published</a>(<a href="Diem.md#0x1_Diem_EMINT_CAPABILITY">EMINT_CAPABILITY</a>)
    );
    move_to(tc_account, mint_cap);
    <a href="Diem.md#0x1_Diem_publish_burn_capability">publish_burn_capability</a>&lt;CoinType&gt;(tc_account, burn_cap);
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="Diem.md#0x1_Diem_RegisterSCSCurrencyAbortsIf">RegisterSCSCurrencyAbortsIf</a>&lt;CoinType&gt;;
<b>include</b> <a href="Diem.md#0x1_Diem_RegisterSCSCurrencyEnsures">RegisterSCSCurrencyEnsures</a>&lt;CoinType&gt;;
</code></pre>




<a name="0x1_Diem_RegisterSCSCurrencyAbortsIf"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_RegisterSCSCurrencyAbortsIf">RegisterSCSCurrencyAbortsIf</a>&lt;CoinType&gt; {
    tc_account: signer;
    dr_account: signer;
    currency_code: vector&lt;u8&gt;;
    scaling_factor: u64;
}
</code></pre>


Must abort if tc_account does not have the TreasuryCompliance role.
Only a TreasuryCompliance account can have the MintCapability [[H1]][PERMISSION].
Only a TreasuryCompliance account can have the BurnCapability [[H3]][PERMISSION].


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_RegisterSCSCurrencyAbortsIf">RegisterSCSCurrencyAbortsIf</a>&lt;CoinType&gt; {
    <b>include</b> <a href="Roles.md#0x1_Roles_AbortsIfNotTreasuryCompliance">Roles::AbortsIfNotTreasuryCompliance</a>{account: tc_account};
    <b>aborts_if</b> <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_MintCapability">MintCapability</a>&lt;CoinType&gt;&gt;(<a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(tc_account)) <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a>;
    <b>include</b> <a href="Diem.md#0x1_Diem_RegisterCurrencyAbortsIf">RegisterCurrencyAbortsIf</a>&lt;CoinType&gt;;
    <b>include</b> <a href="Diem.md#0x1_Diem_PublishBurnCapAbortsIfs">PublishBurnCapAbortsIfs</a>&lt;CoinType&gt;;
}
</code></pre>




<a name="0x1_Diem_RegisterSCSCurrencyEnsures"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_RegisterSCSCurrencyEnsures">RegisterSCSCurrencyEnsures</a>&lt;CoinType&gt; {
    tc_account: signer;
    <b>ensures</b> <a href="Diem.md#0x1_Diem_spec_has_mint_capability">spec_has_mint_capability</a>&lt;CoinType&gt;(<a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(tc_account));
}
</code></pre>



</details>

<a name="0x1_Diem_market_cap"></a>

## Function `market_cap`

Returns the total amount of currency minted of type <code>CoinType</code>.


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_market_cap">market_cap</a>&lt;CoinType&gt;(): u128
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_market_cap">market_cap</a>&lt;CoinType&gt;(): u128
<b>acquires</b> <a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a> {
    <a href="Diem.md#0x1_Diem_assert_is_currency">assert_is_currency</a>&lt;CoinType&gt;();
    borrow_global&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>).total_value
}
</code></pre>



</details>

<a name="0x1_Diem_approx_xdx_for_value"></a>

## Function `approx_xdx_for_value`

Returns the value of the coin in the <code>FromCoinType</code> currency in XDX.
This should only be used where a _rough_ approximation of the exchange
rate is needed.


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_approx_xdx_for_value">approx_xdx_for_value</a>&lt;FromCoinType&gt;(from_value: u64): u64
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_approx_xdx_for_value">approx_xdx_for_value</a>&lt;FromCoinType&gt;(from_value: u64): u64
<b>acquires</b> <a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a> {
    <b>let</b> xdx_exchange_rate = <a href="Diem.md#0x1_Diem_xdx_exchange_rate">xdx_exchange_rate</a>&lt;FromCoinType&gt;();
    <a href="../../../../../../move-stdlib/docs/FixedPoint32.md#0x1_FixedPoint32_multiply_u64">FixedPoint32::multiply_u64</a>(from_value, xdx_exchange_rate)
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>pragma</b> opaque;
<b>include</b> <a href="Diem.md#0x1_Diem_ApproxXdmForValueAbortsIf">ApproxXdmForValueAbortsIf</a>&lt;FromCoinType&gt;;
<b>ensures</b> result == <a href="Diem.md#0x1_Diem_spec_approx_xdx_for_value">spec_approx_xdx_for_value</a>&lt;FromCoinType&gt;(from_value);
</code></pre>




<a name="0x1_Diem_ApproxXdmForValueAbortsIf"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_ApproxXdmForValueAbortsIf">ApproxXdmForValueAbortsIf</a>&lt;CoinType&gt; {
    from_value: num;
    <b>include</b> <a href="Diem.md#0x1_Diem_AbortsIfNoCurrency">AbortsIfNoCurrency</a>&lt;CoinType&gt;;
    <b>let</b> xdx_exchange_rate = <a href="Diem.md#0x1_Diem_spec_xdx_exchange_rate">spec_xdx_exchange_rate</a>&lt;CoinType&gt;();
    <b>include</b> <a href="../../../../../../move-stdlib/docs/FixedPoint32.md#0x1_FixedPoint32_MultiplyAbortsIf">FixedPoint32::MultiplyAbortsIf</a>{val: from_value, multiplier: xdx_exchange_rate};
}
</code></pre>



</details>

<a name="0x1_Diem_approx_xdx_for_coin"></a>

## Function `approx_xdx_for_coin`

Returns the value of the coin in the <code>FromCoinType</code> currency in XDX.
This should only be used where a rough approximation of the exchange
rate is needed.


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_approx_xdx_for_coin">approx_xdx_for_coin</a>&lt;FromCoinType&gt;(coin: &<a href="Diem.md#0x1_Diem_Diem">Diem::Diem</a>&lt;FromCoinType&gt;): u64
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_approx_xdx_for_coin">approx_xdx_for_coin</a>&lt;FromCoinType&gt;(coin: &<a href="Diem.md#0x1_Diem">Diem</a>&lt;FromCoinType&gt;): u64
<b>acquires</b> <a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a> {
    <b>let</b> from_value = <a href="Diem.md#0x1_Diem_value">value</a>(coin);
    <a href="Diem.md#0x1_Diem_approx_xdx_for_value">approx_xdx_for_value</a>&lt;FromCoinType&gt;(from_value)
}
</code></pre>



</details>

<a name="0x1_Diem_is_currency"></a>

## Function `is_currency`

Returns <code><b>true</b></code> if the type <code>CoinType</code> is a registered currency.
Returns <code><b>false</b></code> otherwise.


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_is_currency">is_currency</a>&lt;CoinType&gt;(): bool
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_is_currency">is_currency</a>&lt;CoinType&gt;(): bool {
    <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>)
}
</code></pre>



</details>

<a name="0x1_Diem_is_SCS_currency"></a>

## Function `is_SCS_currency`



<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_is_SCS_currency">is_SCS_currency</a>&lt;CoinType&gt;(): bool
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_is_SCS_currency">is_SCS_currency</a>&lt;CoinType&gt;(): bool <b>acquires</b> <a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a> {
    <a href="Diem.md#0x1_Diem_is_currency">is_currency</a>&lt;CoinType&gt;() &&
    !borrow_global&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>).is_synthetic
}
</code></pre>



</details>

<a name="0x1_Diem_is_synthetic_currency"></a>

## Function `is_synthetic_currency`

Returns <code><b>true</b></code> if <code>CoinType</code> is a synthetic currency as defined in
its <code><a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a></code>. Returns <code><b>false</b></code> otherwise.


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_is_synthetic_currency">is_synthetic_currency</a>&lt;CoinType&gt;(): bool
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_is_synthetic_currency">is_synthetic_currency</a>&lt;CoinType&gt;(): bool
<b>acquires</b> <a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a> {
    <b>let</b> addr = @<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>;
    <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(addr) &&
        borrow_global&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(addr).is_synthetic
}
</code></pre>



</details>

<a name="0x1_Diem_scaling_factor"></a>

## Function `scaling_factor`

Returns the scaling factor for the <code>CoinType</code> currency as defined
in its <code><a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a></code>.


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_scaling_factor">scaling_factor</a>&lt;CoinType&gt;(): u64
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_scaling_factor">scaling_factor</a>&lt;CoinType&gt;(): u64
<b>acquires</b> <a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a> {
    <a href="Diem.md#0x1_Diem_assert_is_currency">assert_is_currency</a>&lt;CoinType&gt;();
    borrow_global&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>).scaling_factor
}
</code></pre>



</details>

<a name="0x1_Diem_fractional_part"></a>

## Function `fractional_part`

Returns the representable (i.e. real-world) fractional part for the
<code>CoinType</code> currency as defined in its <code><a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a></code>.


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_fractional_part">fractional_part</a>&lt;CoinType&gt;(): u64
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_fractional_part">fractional_part</a>&lt;CoinType&gt;(): u64
<b>acquires</b> <a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a> {
    <a href="Diem.md#0x1_Diem_assert_is_currency">assert_is_currency</a>&lt;CoinType&gt;();
    borrow_global&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>).fractional_part
}
</code></pre>



</details>

<a name="0x1_Diem_currency_code"></a>

## Function `currency_code`

Returns the currency code for the registered currency as defined in
its <code><a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a></code> resource.


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_currency_code">currency_code</a>&lt;CoinType&gt;(): vector&lt;u8&gt;
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_currency_code">currency_code</a>&lt;CoinType&gt;(): vector&lt;u8&gt;
<b>acquires</b> <a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a> {
    <a href="Diem.md#0x1_Diem_assert_is_currency">assert_is_currency</a>&lt;CoinType&gt;();
    *&borrow_global&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>).currency_code
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>pragma</b> opaque;
<b>include</b> <a href="Diem.md#0x1_Diem_AbortsIfNoCurrency">AbortsIfNoCurrency</a>&lt;CoinType&gt;;
<b>ensures</b> result == <a href="Diem.md#0x1_Diem_spec_currency_code">spec_currency_code</a>&lt;CoinType&gt;();
</code></pre>




<a name="0x1_Diem_spec_currency_code"></a>


<pre><code><b>fun</b> <a href="Diem.md#0x1_Diem_spec_currency_code">spec_currency_code</a>&lt;CoinType&gt;(): vector&lt;u8&gt; {
   <a href="Diem.md#0x1_Diem_spec_currency_info">spec_currency_info</a>&lt;CoinType&gt;().currency_code
}
</code></pre>



</details>

<a name="0x1_Diem_update_xdx_exchange_rate"></a>

## Function `update_xdx_exchange_rate`

Updates the <code>to_xdx_exchange_rate</code> held in the <code><a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a></code> for
<code>FromCoinType</code> to the new passed-in <code>xdx_exchange_rate</code>.


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_update_xdx_exchange_rate">update_xdx_exchange_rate</a>&lt;FromCoinType&gt;(tc_account: &signer, xdx_exchange_rate: <a href="../../../../../../move-stdlib/docs/FixedPoint32.md#0x1_FixedPoint32_FixedPoint32">FixedPoint32::FixedPoint32</a>)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_update_xdx_exchange_rate">update_xdx_exchange_rate</a>&lt;FromCoinType&gt;(
    tc_account: &signer,
    xdx_exchange_rate: <a href="../../../../../../move-stdlib/docs/FixedPoint32.md#0x1_FixedPoint32">FixedPoint32</a>
) <b>acquires</b> <a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a> {
    <a href="Roles.md#0x1_Roles_assert_treasury_compliance">Roles::assert_treasury_compliance</a>(tc_account);
    <a href="Diem.md#0x1_Diem_assert_is_currency">assert_is_currency</a>&lt;FromCoinType&gt;();
    <b>let</b> currency_info = borrow_global_mut&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;FromCoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>);
    currency_info.to_xdx_exchange_rate = xdx_exchange_rate;
    <a href="../../../../../../move-stdlib/docs/Event.md#0x1_Event_emit_event">Event::emit_event</a>(
        &<b>mut</b> currency_info.exchange_rate_update_events,
        <a href="Diem.md#0x1_Diem_ToXDXExchangeRateUpdateEvent">ToXDXExchangeRateUpdateEvent</a> {
            currency_code: *&currency_info.currency_code,
            new_to_xdx_exchange_rate: <a href="../../../../../../move-stdlib/docs/FixedPoint32.md#0x1_FixedPoint32_get_raw_value">FixedPoint32::get_raw_value</a>(*&currency_info.to_xdx_exchange_rate),
        }
    );
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="Diem.md#0x1_Diem_UpdateXDXExchangeRateAbortsIf">UpdateXDXExchangeRateAbortsIf</a>&lt;FromCoinType&gt;;
<b>include</b> <a href="Diem.md#0x1_Diem_UpdateXDXExchangeRateEnsures">UpdateXDXExchangeRateEnsures</a>&lt;FromCoinType&gt;;
<b>include</b> <a href="Diem.md#0x1_Diem_UpdateXDXExchangeRateEmits">UpdateXDXExchangeRateEmits</a>&lt;FromCoinType&gt;;
</code></pre>




<a name="0x1_Diem_UpdateXDXExchangeRateAbortsIf"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_UpdateXDXExchangeRateAbortsIf">UpdateXDXExchangeRateAbortsIf</a>&lt;FromCoinType&gt; {
    tc_account: signer;
}
</code></pre>


Must abort if the account does not have the TreasuryCompliance Role [[H5]][PERMISSION].


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_UpdateXDXExchangeRateAbortsIf">UpdateXDXExchangeRateAbortsIf</a>&lt;FromCoinType&gt; {
    <b>include</b> <a href="Roles.md#0x1_Roles_AbortsIfNotTreasuryCompliance">Roles::AbortsIfNotTreasuryCompliance</a>{account: tc_account};
    <b>include</b> <a href="Diem.md#0x1_Diem_AbortsIfNoCurrency">AbortsIfNoCurrency</a>&lt;FromCoinType&gt;;
}
</code></pre>




<a name="0x1_Diem_UpdateXDXExchangeRateEnsures"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_UpdateXDXExchangeRateEnsures">UpdateXDXExchangeRateEnsures</a>&lt;FromCoinType&gt; {
    xdx_exchange_rate: <a href="../../../../../../move-stdlib/docs/FixedPoint32.md#0x1_FixedPoint32">FixedPoint32</a>;
    <b>ensures</b> <a href="Diem.md#0x1_Diem_spec_currency_info">spec_currency_info</a>&lt;FromCoinType&gt;().to_xdx_exchange_rate == xdx_exchange_rate;
}
</code></pre>




<a name="0x1_Diem_UpdateXDXExchangeRateEmits"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_UpdateXDXExchangeRateEmits">UpdateXDXExchangeRateEmits</a>&lt;FromCoinType&gt; {
    xdx_exchange_rate: <a href="../../../../../../move-stdlib/docs/FixedPoint32.md#0x1_FixedPoint32">FixedPoint32</a>;
    <b>let</b> handle = <b>global</b>&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;FromCoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>).exchange_rate_update_events;
    <b>let</b> msg = <a href="Diem.md#0x1_Diem_ToXDXExchangeRateUpdateEvent">ToXDXExchangeRateUpdateEvent</a> {
        currency_code: <b>global</b>&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;FromCoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>).currency_code,
        new_to_xdx_exchange_rate: <a href="../../../../../../move-stdlib/docs/FixedPoint32.md#0x1_FixedPoint32_get_raw_value">FixedPoint32::get_raw_value</a>(xdx_exchange_rate)
    };
    emits msg <b>to</b> handle;
}
</code></pre>



</details>

<a name="0x1_Diem_xdx_exchange_rate"></a>

## Function `xdx_exchange_rate`

Returns the (rough) exchange rate between <code>CoinType</code> and <code><a href="XDX.md#0x1_XDX">XDX</a></code>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_xdx_exchange_rate">xdx_exchange_rate</a>&lt;CoinType&gt;(): <a href="../../../../../../move-stdlib/docs/FixedPoint32.md#0x1_FixedPoint32_FixedPoint32">FixedPoint32::FixedPoint32</a>
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_xdx_exchange_rate">xdx_exchange_rate</a>&lt;CoinType&gt;(): <a href="../../../../../../move-stdlib/docs/FixedPoint32.md#0x1_FixedPoint32">FixedPoint32</a>
<b>acquires</b> <a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a> {
    <a href="Diem.md#0x1_Diem_assert_is_currency">assert_is_currency</a>&lt;CoinType&gt;();
    *&borrow_global&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>).to_xdx_exchange_rate
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>pragma</b> opaque;
<b>include</b> <a href="Diem.md#0x1_Diem_AbortsIfNoCurrency">AbortsIfNoCurrency</a>&lt;CoinType&gt;;
<b>let</b> info = <b>global</b>&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>);
<b>ensures</b> result == info.to_xdx_exchange_rate;
</code></pre>



</details>

<a name="0x1_Diem_update_minting_ability"></a>

## Function `update_minting_ability`

There may be situations in which we disallow the further minting of
coins in the system without removing the currency. This function
allows the association treasury compliance account to control whether or not further coins of
<code>CoinType</code> can be minted or not. If this is called with <code>can_mint = <b>true</b></code>,
then minting is allowed, if <code>can_mint = <b>false</b></code> then minting is
disallowed until it is turned back on via this function. All coins
start out in the default state of <code>can_mint = <b>true</b></code>.


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_update_minting_ability">update_minting_ability</a>&lt;CoinType&gt;(tc_account: &signer, can_mint: bool)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_update_minting_ability">update_minting_ability</a>&lt;CoinType&gt;(
    tc_account: &signer,
    can_mint: bool,
    )
<b>acquires</b> <a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a> {
    <a href="Roles.md#0x1_Roles_assert_treasury_compliance">Roles::assert_treasury_compliance</a>(tc_account);
    <a href="Diem.md#0x1_Diem_assert_is_currency">assert_is_currency</a>&lt;CoinType&gt;();
    <b>let</b> currency_info = borrow_global_mut&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>);
    currency_info.can_mint = can_mint;
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="Diem.md#0x1_Diem_UpdateMintingAbilityAbortsIf">UpdateMintingAbilityAbortsIf</a>&lt;CoinType&gt;;
<b>include</b> <a href="Diem.md#0x1_Diem_UpdateMintingAbilityEnsures">UpdateMintingAbilityEnsures</a>&lt;CoinType&gt;;
</code></pre>




<a name="0x1_Diem_UpdateMintingAbilityAbortsIf"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_UpdateMintingAbilityAbortsIf">UpdateMintingAbilityAbortsIf</a>&lt;CoinType&gt; {
    tc_account: signer;
    <b>include</b> <a href="Diem.md#0x1_Diem_AbortsIfNoCurrency">AbortsIfNoCurrency</a>&lt;CoinType&gt;;
}
</code></pre>


Only the TreasuryCompliance role can enable/disable minting [[H2]][PERMISSION].


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_UpdateMintingAbilityAbortsIf">UpdateMintingAbilityAbortsIf</a>&lt;CoinType&gt; {
    <b>include</b> <a href="Roles.md#0x1_Roles_AbortsIfNotTreasuryCompliance">Roles::AbortsIfNotTreasuryCompliance</a>{account: tc_account};
}
</code></pre>




<a name="0x1_Diem_UpdateMintingAbilityEnsures"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_UpdateMintingAbilityEnsures">UpdateMintingAbilityEnsures</a>&lt;CoinType&gt; {
    tc_account: signer;
    can_mint: bool;
    <b>ensures</b> <a href="Diem.md#0x1_Diem_spec_currency_info">spec_currency_info</a>&lt;CoinType&gt;().can_mint == can_mint;
}
</code></pre>



</details>

<a name="0x1_Diem_assert_is_currency"></a>

## Function `assert_is_currency`

Asserts that <code>CoinType</code> is a registered currency.


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_assert_is_currency">assert_is_currency</a>&lt;CoinType&gt;()
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_assert_is_currency">assert_is_currency</a>&lt;CoinType&gt;() {
    <b>assert</b>(<a href="Diem.md#0x1_Diem_is_currency">is_currency</a>&lt;CoinType&gt;(), <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_not_published">Errors::not_published</a>(<a href="Diem.md#0x1_Diem_ECURRENCY_INFO">ECURRENCY_INFO</a>));
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>pragma</b> opaque;
<b>include</b> <a href="Diem.md#0x1_Diem_AbortsIfNoCurrency">AbortsIfNoCurrency</a>&lt;CoinType&gt;;
</code></pre>




<a name="0x1_Diem_AbortsIfNoCurrency"></a>


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_AbortsIfNoCurrency">AbortsIfNoCurrency</a>&lt;CoinType&gt; {
    <b>aborts_if</b> !<a href="Diem.md#0x1_Diem_spec_is_currency">spec_is_currency</a>&lt;CoinType&gt;() <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>;
}
</code></pre>



</details>

<a name="0x1_Diem_assert_is_SCS_currency"></a>

## Function `assert_is_SCS_currency`



<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_assert_is_SCS_currency">assert_is_SCS_currency</a>&lt;CoinType&gt;()
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Diem.md#0x1_Diem_assert_is_SCS_currency">assert_is_SCS_currency</a>&lt;CoinType&gt;() <b>acquires</b> <a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a> {
    <a href="Diem.md#0x1_Diem_assert_is_currency">assert_is_currency</a>&lt;CoinType&gt;();
    <b>assert</b>(<a href="Diem.md#0x1_Diem_is_SCS_currency">is_SCS_currency</a>&lt;CoinType&gt;(), <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_invalid_state">Errors::invalid_state</a>(<a href="Diem.md#0x1_Diem_ECURRENCY_INFO">ECURRENCY_INFO</a>));
}
</code></pre>



</details>

<a name="@Module_Specification_1"></a>

## Module Specification

Returns the market cap of CoinType.


<a name="0x1_Diem_spec_market_cap"></a>


<pre><code><b>fun</b> <a href="Diem.md#0x1_Diem_spec_market_cap">spec_market_cap</a>&lt;CoinType&gt;(): u128 {
   <b>global</b>&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>).total_value
}
</code></pre>




<a name="0x1_Diem_spec_scaling_factor"></a>


<pre><code><b>fun</b> <a href="Diem.md#0x1_Diem_spec_scaling_factor">spec_scaling_factor</a>&lt;CoinType&gt;(): u64 {
   <b>global</b>&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>).scaling_factor
}
</code></pre>




<a name="@Access_Control_2"></a>

### Access Control


Only mint functions can increase the total amount of currency [[H1]][PERMISSION].


<pre><code><b>apply</b> <a href="Diem.md#0x1_Diem_TotalValueNotIncrease">TotalValueNotIncrease</a>&lt;CoinType&gt; <b>to</b> *&lt;CoinType&gt;
    <b>except</b> <a href="Diem.md#0x1_Diem_mint">mint</a>&lt;CoinType&gt;, <a href="Diem.md#0x1_Diem_mint_with_capability">mint_with_capability</a>&lt;CoinType&gt;;
</code></pre>


In order to successfully call <code>mint</code> and <code>mint_with_capability</code>, MintCapability is
required. MintCapability must be only granted to a TreasuryCompliance account [[H1]][PERMISSION].
Only <code>register_SCS_currency</code> creates MintCapability, which must abort if the account
does not have the TreasuryCompliance role [[H1]][PERMISSION].


<pre><code><b>apply</b> <a href="Diem.md#0x1_Diem_PreserveMintCapAbsence">PreserveMintCapAbsence</a>&lt;CoinType&gt; <b>to</b> *&lt;CoinType&gt; <b>except</b> <a href="Diem.md#0x1_Diem_register_SCS_currency">register_SCS_currency</a>&lt;CoinType&gt;;
<b>apply</b> <a href="Roles.md#0x1_Roles_AbortsIfNotTreasuryCompliance">Roles::AbortsIfNotTreasuryCompliance</a>{account: tc_account} <b>to</b> <a href="Diem.md#0x1_Diem_register_SCS_currency">register_SCS_currency</a>&lt;CoinType&gt;;
</code></pre>


Only TreasuryCompliance can have MintCapability [[H1]][PERMISSION].
If an account has MintCapability, it is a TreasuryCompliance account.


<pre><code><b>invariant</b> <b>forall</b> coin_type: type:
    <b>forall</b> mint_cap_owner: address <b>where</b> <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_MintCapability">MintCapability</a>&lt;coin_type&gt;&gt;(mint_cap_owner):
        <a href="Roles.md#0x1_Roles_spec_has_treasury_compliance_role_addr">Roles::spec_has_treasury_compliance_role_addr</a>(mint_cap_owner);
</code></pre>


MintCapability is not transferrable [[J1]][PERMISSION].


<pre><code><b>apply</b> <a href="Diem.md#0x1_Diem_PreserveMintCapExistence">PreserveMintCapExistence</a>&lt;CoinType&gt; <b>to</b> *&lt;CoinType&gt;;
</code></pre>


The permission "MintCurrency" is unique per currency [[I1]][PERMISSION].
At most one address has a mint capability for SCS CoinType


<pre><code><b>invariant</b> [<b>global</b>, isolated]
    <b>forall</b> coin_type: type <b>where</b> <a href="Diem.md#0x1_Diem_is_SCS_currency">is_SCS_currency</a>&lt;coin_type&gt;():
        <b>forall</b> mint_cap_owner1: address, mint_cap_owner2: address
             <b>where</b> <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_MintCapability">MintCapability</a>&lt;coin_type&gt;&gt;(mint_cap_owner1)
                        && <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_MintCapability">MintCapability</a>&lt;coin_type&gt;&gt;(mint_cap_owner2):
                  mint_cap_owner1 == mint_cap_owner2;
</code></pre>


If an address has a mint capability, it is an SCS currency.


<pre><code><b>invariant</b>
    <b>forall</b> coin_type: type, addr3: address <b>where</b> <a href="Diem.md#0x1_Diem_spec_has_mint_capability">spec_has_mint_capability</a>&lt;coin_type&gt;(addr3):
        <a href="Diem.md#0x1_Diem_is_SCS_currency">is_SCS_currency</a>&lt;coin_type&gt;();
</code></pre>



<a name="@Minting_3"></a>

#### Minting



<a name="0x1_Diem_TotalValueNotIncrease"></a>

The total amount of currency does not increase.


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_TotalValueNotIncrease">TotalValueNotIncrease</a>&lt;CoinType&gt; {
    <b>ensures</b> <b>old</b>(<a href="Diem.md#0x1_Diem_spec_is_currency">spec_is_currency</a>&lt;CoinType&gt;())
        ==&gt; <a href="Diem.md#0x1_Diem_spec_currency_info">spec_currency_info</a>&lt;CoinType&gt;().total_value &lt;= <b>old</b>(<a href="Diem.md#0x1_Diem_spec_currency_info">spec_currency_info</a>&lt;CoinType&gt;().total_value);
}
</code></pre>




<a name="0x1_Diem_PreserveMintCapExistence"></a>

The existence of MintCapability is preserved.


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_PreserveMintCapExistence">PreserveMintCapExistence</a>&lt;CoinType&gt; {
    <b>ensures</b> <b>forall</b> addr: address:
        <b>old</b>(<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_MintCapability">MintCapability</a>&lt;CoinType&gt;&gt;(addr)) ==&gt;
            <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_MintCapability">MintCapability</a>&lt;CoinType&gt;&gt;(addr);
}
</code></pre>




<a name="0x1_Diem_PreserveMintCapAbsence"></a>

The absence of MintCapability is preserved.


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_PreserveMintCapAbsence">PreserveMintCapAbsence</a>&lt;CoinType&gt; {
    <b>ensures</b> <b>forall</b> addr: address:
        <b>old</b>(!<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_MintCapability">MintCapability</a>&lt;CoinType&gt;&gt;(addr)) ==&gt;
            !<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_MintCapability">MintCapability</a>&lt;CoinType&gt;&gt;(addr);
}
</code></pre>



<a name="@Burning_4"></a>

#### Burning



<a name="0x1_Diem_TotalValueNotDecrease"></a>

The total amount of currency does not decrease.


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_TotalValueNotDecrease">TotalValueNotDecrease</a>&lt;CoinType&gt; {
    <b>ensures</b> <b>old</b>(<a href="Diem.md#0x1_Diem_spec_is_currency">spec_is_currency</a>&lt;CoinType&gt;())
        ==&gt; <a href="Diem.md#0x1_Diem_spec_currency_info">spec_currency_info</a>&lt;CoinType&gt;().total_value &gt;= <b>old</b>(<a href="Diem.md#0x1_Diem_spec_currency_info">spec_currency_info</a>&lt;CoinType&gt;().total_value);
}
</code></pre>




<a name="0x1_Diem_PreserveBurnCapExistence"></a>

The existence of BurnCapability is preserved.


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_PreserveBurnCapExistence">PreserveBurnCapExistence</a>&lt;CoinType&gt; {
    <b>ensures</b> <b>forall</b> addr: address:
        <b>old</b>(<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>&lt;CoinType&gt;&gt;(addr)) ==&gt;
            <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>&lt;CoinType&gt;&gt;(addr);
}
</code></pre>




<a name="0x1_Diem_PreserveBurnCapAbsence"></a>

The absence of BurnCapability is preserved.


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_PreserveBurnCapAbsence">PreserveBurnCapAbsence</a>&lt;CoinType&gt; {
    <b>ensures</b> <b>forall</b> addr: address:
        <b>old</b>(!<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>&lt;CoinType&gt;&gt;(addr)) ==&gt;
            !<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>&lt;CoinType&gt;&gt;(addr);
}
</code></pre>



Only burn functions can decrease the total amount of currency [[H3]][PERMISSION].


<pre><code><b>apply</b> <a href="Diem.md#0x1_Diem_TotalValueNotDecrease">TotalValueNotDecrease</a>&lt;CoinType&gt; <b>to</b> *&lt;CoinType&gt;
    <b>except</b> <a href="Diem.md#0x1_Diem_burn">burn</a>&lt;CoinType&gt;, <a href="Diem.md#0x1_Diem_burn_with_capability">burn_with_capability</a>&lt;CoinType&gt;, <a href="Diem.md#0x1_Diem_burn_with_resource_cap">burn_with_resource_cap</a>&lt;CoinType&gt;,
    <a href="Diem.md#0x1_Diem_burn_now">burn_now</a>&lt;CoinType&gt;;
</code></pre>


In order to successfully call the burn functions, BurnCapability is required.
BurnCapability must be only granted to a TreasuryCompliance account [[H3]][PERMISSION].
Only <code>register_SCS_currency</code> and <code>publish_burn_capability</code> publish BurnCapability,
which must abort if the account does not have the TreasuryCompliance role [[H8]][PERMISSION].


<pre><code><b>apply</b> <a href="Diem.md#0x1_Diem_PreserveBurnCapAbsence">PreserveBurnCapAbsence</a>&lt;CoinType&gt; <b>to</b> *&lt;CoinType&gt;
    <b>except</b> <a href="Diem.md#0x1_Diem_register_SCS_currency">register_SCS_currency</a>&lt;CoinType&gt;, <a href="Diem.md#0x1_Diem_publish_burn_capability">publish_burn_capability</a>&lt;CoinType&gt;;
<b>apply</b> <a href="Roles.md#0x1_Roles_AbortsIfNotTreasuryCompliance">Roles::AbortsIfNotTreasuryCompliance</a>{account: tc_account} <b>to</b> <a href="Diem.md#0x1_Diem_register_SCS_currency">register_SCS_currency</a>&lt;CoinType&gt;;
</code></pre>


Only TreasuryCompliance can have BurnCapability [[H3]][PERMISSION].
If an account has BurnCapability, it is a TreasuryCompliance account.


<pre><code><b>invariant</b> <b>forall</b> coin_type: type:
    <b>forall</b> addr1: address:
        <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>&lt;coin_type&gt;&gt;(addr1) ==&gt;
            <a href="Roles.md#0x1_Roles_spec_has_treasury_compliance_role_addr">Roles::spec_has_treasury_compliance_role_addr</a>(addr1);
</code></pre>


BurnCapability is not transferrable [[J3]][PERMISSION]. BurnCapability can be extracted from an
account, but is always moved back to the original account. This is the case in
<code><a href="TransactionFee.md#0x1_TransactionFee_burn_fees">TransactionFee::burn_fees</a></code> which is the only user of <code>remove_burn_capability</code> and
<code>publish_burn_capability</code>.


<pre><code><b>apply</b> <a href="Diem.md#0x1_Diem_PreserveBurnCapExistence">PreserveBurnCapExistence</a>&lt;CoinType&gt; <b>to</b> *&lt;CoinType&gt; <b>except</b> <a href="Diem.md#0x1_Diem_remove_burn_capability">remove_burn_capability</a>&lt;CoinType&gt;;
</code></pre>



<a name="@Preburning_5"></a>

#### Preburning



<a name="0x1_Diem_PreburnValueNotIncrease"></a>

The preburn value of currency does not increase.


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_PreburnValueNotIncrease">PreburnValueNotIncrease</a>&lt;CoinType&gt; {
    <b>ensures</b> <b>old</b>(<a href="Diem.md#0x1_Diem_spec_is_currency">spec_is_currency</a>&lt;CoinType&gt;())
        ==&gt; <a href="Diem.md#0x1_Diem_spec_currency_info">spec_currency_info</a>&lt;CoinType&gt;().<a href="Diem.md#0x1_Diem_preburn_value">preburn_value</a> &lt;= <b>old</b>(<a href="Diem.md#0x1_Diem_spec_currency_info">spec_currency_info</a>&lt;CoinType&gt;().preburn_value);
}
</code></pre>




<a name="0x1_Diem_PreburnValueNotDecrease"></a>

The the preburn value of currency does not decrease.


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_PreburnValueNotDecrease">PreburnValueNotDecrease</a>&lt;CoinType&gt; {
    <b>ensures</b> <b>old</b>(<a href="Diem.md#0x1_Diem_spec_is_currency">spec_is_currency</a>&lt;CoinType&gt;())
        ==&gt; <a href="Diem.md#0x1_Diem_spec_currency_info">spec_currency_info</a>&lt;CoinType&gt;().preburn_value &gt;= <b>old</b>(<a href="Diem.md#0x1_Diem_spec_currency_info">spec_currency_info</a>&lt;CoinType&gt;().preburn_value);
}
</code></pre>




<a name="0x1_Diem_PreservePreburnQueueExistence"></a>

The existence of the <code><a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a></code> resource is preserved.


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_PreservePreburnQueueExistence">PreservePreburnQueueExistence</a>&lt;CoinType&gt; {
    <b>ensures</b> <b>forall</b> addr: address:
        <b>old</b>(<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(addr)) ==&gt;
            <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(addr);
}
</code></pre>




<a name="0x1_Diem_PreservePreburnQueueAbsence"></a>

The absence of a <code><a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a></code> is preserved.
> NB: As part of the upgrade process, we also tie this in with the
non-existence of a <code><a href="Diem.md#0x1_Diem_Preburn">Preburn</a></code> resource as well. Once the upgrade
process is complete this additional existence check can be removed.


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_PreservePreburnQueueAbsence">PreservePreburnQueueAbsence</a>&lt;CoinType&gt; {
    <b>ensures</b> <b>forall</b> addr: address:
        <b>old</b>(!(<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(addr) || <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_Preburn">Preburn</a>&lt;CoinType&gt;&gt;(addr))) ==&gt;
            !<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;&gt;(addr);
}
</code></pre>



Only burn functions can decrease the preburn value of currency [[H4]][PERMISSION].


<pre><code><b>apply</b> <a href="Diem.md#0x1_Diem_PreburnValueNotDecrease">PreburnValueNotDecrease</a>&lt;CoinType&gt; <b>to</b> *&lt;CoinType&gt;
    <b>except</b> <a href="Diem.md#0x1_Diem_burn">burn</a>&lt;CoinType&gt;, <a href="Diem.md#0x1_Diem_burn_with_capability">burn_with_capability</a>&lt;CoinType&gt;, <a href="Diem.md#0x1_Diem_burn_with_resource_cap">burn_with_resource_cap</a>&lt;CoinType&gt;,
    <a href="Diem.md#0x1_Diem_burn_now">burn_now</a>&lt;CoinType&gt;, <a href="Diem.md#0x1_Diem_cancel_burn">cancel_burn</a>&lt;CoinType&gt;, <a href="Diem.md#0x1_Diem_cancel_burn_with_capability">cancel_burn_with_capability</a>&lt;CoinType&gt;;
</code></pre>


Only preburn functions can increase the preburn value of currency [[H4]][PERMISSION].


<pre><code><b>apply</b> <a href="Diem.md#0x1_Diem_PreburnValueNotIncrease">PreburnValueNotIncrease</a>&lt;CoinType&gt; <b>to</b> *&lt;CoinType&gt;
    <b>except</b> <a href="Diem.md#0x1_Diem_preburn_to">preburn_to</a>&lt;CoinType&gt;, <a href="Diem.md#0x1_Diem_preburn_with_resource">preburn_with_resource</a>&lt;CoinType&gt;;
</code></pre>


In order to successfully call the preburn functions, Preburn is required. Preburn must
be only granted to a DesignatedDealer account [[H4]][PERMISSION]. Only <code>publish_preburn_queue_to_account</code> and <code>publish_preburn_queue</code>
publishes <code><a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a></code>, which must abort if the account does not have the DesignatedDealer role [[H4]][PERMISSION].


<pre><code><b>apply</b> <a href="Roles.md#0x1_Roles_AbortsIfNotDesignatedDealer">Roles::AbortsIfNotDesignatedDealer</a> <b>to</b> <a href="Diem.md#0x1_Diem_publish_preburn_queue">publish_preburn_queue</a>&lt;CoinType&gt;, <a href="Diem.md#0x1_Diem_publish_preburn_queue_to_account">publish_preburn_queue_to_account</a>&lt;CoinType&gt;;
<b>apply</b> <a href="Diem.md#0x1_Diem_PreservePreburnQueueAbsence">PreservePreburnQueueAbsence</a>&lt;CoinType&gt; <b>to</b> *&lt;CoinType&gt; <b>except</b>
    <a href="Diem.md#0x1_Diem_publish_preburn_queue">publish_preburn_queue</a>&lt;CoinType&gt;,
    <a href="Diem.md#0x1_Diem_publish_preburn_queue_to_account">publish_preburn_queue_to_account</a>&lt;CoinType&gt;;
</code></pre>


Only DesignatedDealer can have PreburnQueue [[H3]][PERMISSION].
If an account has PreburnQueue, it is a DesignatedDealer account.
> NB: during the transition this holds for both <code><a href="Diem.md#0x1_Diem_Preburn">Preburn</a></code> and <code><a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a></code> resources.


<pre><code><b>invariant</b> <b>forall</b> coin_type: type:
    <b>forall</b> addr1: address:
        <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;coin_type&gt;&gt;(addr1) || <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_Preburn">Preburn</a>&lt;coin_type&gt;&gt;(addr1) ==&gt;
            <a href="Roles.md#0x1_Roles_spec_has_designated_dealer_role_addr">Roles::spec_has_designated_dealer_role_addr</a>(addr1);
</code></pre>


If there is a preburn resource published, it must have a value of zero.
If there is a preburn resource published, there cannot also be a
<code><a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a></code> resource published under that same account for the
same currency.
> NB: This invariant is part of the upgrade process, eventually
this will be removed once all DD's have been upgraded to
using the <code><a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a></code>.


<pre><code><b>invariant</b> <b>forall</b> coin_type: type, dd_addr: address
    <b>where</b> <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_Preburn">Preburn</a>&lt;coin_type&gt;&gt;(dd_addr):
        <b>global</b>&lt;<a href="Diem.md#0x1_Diem_Preburn">Preburn</a>&lt;coin_type&gt;&gt;(dd_addr).to_burn.value == 0 &&
        !<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;coin_type&gt;&gt;(dd_addr);
</code></pre>


If there is a <code><a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a></code> resource published, then there cannot
also be a <code><a href="Diem.md#0x1_Diem_Preburn">Preburn</a></code> resource for that same currency published under
the same address.


<pre><code><b>invariant</b> <b>forall</b> coin_type: type, dd_addr: address
    <b>where</b> <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;coin_type&gt;&gt;(dd_addr):
        !<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_Preburn">Preburn</a>&lt;coin_type&gt;&gt;(dd_addr);
</code></pre>


A <code><a href="Diem.md#0x1_Diem_Preburn">Preburn</a></code> resource can only be published holding a currency type.


<pre><code><b>invariant</b> <b>forall</b> addr: address, coin_type: type
    <b>where</b> <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_Preburn">Preburn</a>&lt;coin_type&gt;&gt;(addr):
    <a href="Diem.md#0x1_Diem_spec_is_currency">spec_is_currency</a>&lt;coin_type&gt;();
</code></pre>


A <code><a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a></code> resource can only be published holding a currency type.


<pre><code><b>invariant</b> <b>forall</b> addr: address, coin_type: type
    <b>where</b> <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;coin_type&gt;&gt;(addr):
    <a href="Diem.md#0x1_Diem_spec_is_currency">spec_is_currency</a>&lt;coin_type&gt;();
</code></pre>


Preburn is not transferrable [[J4]][PERMISSION].


<pre><code><b>apply</b> <a href="Diem.md#0x1_Diem_PreservePreburnQueueExistence">PreservePreburnQueueExistence</a>&lt;CoinType&gt; <b>to</b> *&lt;CoinType&gt;;
</code></pre>


resource struct <code><a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a></code> is persistent


<pre><code><b>invariant</b> <b>update</b> <b>forall</b> coin_type: type, dr_addr: address
    <b>where</b> <b>old</b>(<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;coin_type&gt;&gt;(dr_addr)):
        <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;coin_type&gt;&gt;(dr_addr);
</code></pre>


resource struct <code><a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;CoinType&gt;</code> is persistent


<pre><code><b>invariant</b> <b>update</b> <b>forall</b> coin_type: type, tc_addr: address
    <b>where</b> <b>old</b>(<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;coin_type&gt;&gt;(tc_addr)):
        <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">PreburnQueue</a>&lt;coin_type&gt;&gt;(tc_addr);
</code></pre>


resource struct <code><a href="Diem.md#0x1_Diem_MintCapability">MintCapability</a>&lt;CoinType&gt;</code> is persistent


<pre><code><b>invariant</b> <b>update</b> <b>forall</b> coin_type: type, tc_addr: address
    <b>where</b> <b>old</b>(<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_MintCapability">MintCapability</a>&lt;coin_type&gt;&gt;(tc_addr)):
        <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_MintCapability">MintCapability</a>&lt;coin_type&gt;&gt;(tc_addr);
</code></pre>



<a name="@Update_Exchange_Rates_6"></a>

#### Update Exchange Rates



<a name="0x1_Diem_ExchangeRateRemainsSame"></a>

The exchange rate to XDX stays constant.


<pre><code><b>schema</b> <a href="Diem.md#0x1_Diem_ExchangeRateRemainsSame">ExchangeRateRemainsSame</a>&lt;CoinType&gt; {
    <b>ensures</b> <b>old</b>(<a href="Diem.md#0x1_Diem_spec_is_currency">spec_is_currency</a>&lt;CoinType&gt;())
        ==&gt; <a href="Diem.md#0x1_Diem_spec_currency_info">spec_currency_info</a>&lt;CoinType&gt;().to_xdx_exchange_rate
            == <b>old</b>(<a href="Diem.md#0x1_Diem_spec_currency_info">spec_currency_info</a>&lt;CoinType&gt;().to_xdx_exchange_rate);
}
</code></pre>



The permission "UpdateExchangeRate(type)" is granted to TreasuryCompliance [[H5]][PERMISSION].


<pre><code><b>apply</b> <a href="Roles.md#0x1_Roles_AbortsIfNotTreasuryCompliance">Roles::AbortsIfNotTreasuryCompliance</a>{account: tc_account} <b>to</b> <a href="Diem.md#0x1_Diem_update_xdx_exchange_rate">update_xdx_exchange_rate</a>&lt;FromCoinType&gt;;
</code></pre>


Only update_xdx_exchange_rate can change the exchange rate [[H5]][PERMISSION].


<pre><code><b>apply</b> <a href="Diem.md#0x1_Diem_ExchangeRateRemainsSame">ExchangeRateRemainsSame</a>&lt;CoinType&gt; <b>to</b> *&lt;CoinType&gt;
    <b>except</b> <a href="Diem.md#0x1_Diem_update_xdx_exchange_rate">update_xdx_exchange_rate</a>&lt;CoinType&gt;;
</code></pre>



<a name="@Helper_Functions_7"></a>

### Helper Functions


Checks whether currency is registered. Mirrors <code><a href="Diem.md#0x1_Diem_is_currency">Self::is_currency</a>&lt;CoinType&gt;</code>.


<a name="0x1_Diem_spec_is_currency"></a>


<pre><code><b>fun</b> <a href="Diem.md#0x1_Diem_spec_is_currency">spec_is_currency</a>&lt;CoinType&gt;(): bool {
    <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>)
}
</code></pre>


Returns currency information.


<a name="0x1_Diem_spec_currency_info"></a>


<pre><code><b>fun</b> <a href="Diem.md#0x1_Diem_spec_currency_info">spec_currency_info</a>&lt;CoinType&gt;(): <a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt; {
    <b>global</b>&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>)
}
</code></pre>


Specification version of <code><a href="Diem.md#0x1_Diem_approx_xdx_for_value">Self::approx_xdx_for_value</a></code>.


<a name="0x1_Diem_spec_approx_xdx_for_value"></a>


<pre><code><b>fun</b> <a href="Diem.md#0x1_Diem_spec_approx_xdx_for_value">spec_approx_xdx_for_value</a>&lt;CoinType&gt;(value: num):  num {
    <a href="../../../../../../move-stdlib/docs/FixedPoint32.md#0x1_FixedPoint32_spec_multiply_u64">FixedPoint32::spec_multiply_u64</a>(value, <a href="Diem.md#0x1_Diem_spec_xdx_exchange_rate">spec_xdx_exchange_rate</a>&lt;CoinType&gt;())
}
<a name="0x1_Diem_spec_xdx_exchange_rate"></a>
<b>fun</b> <a href="Diem.md#0x1_Diem_spec_xdx_exchange_rate">spec_xdx_exchange_rate</a>&lt;CoinType&gt;(): <a href="../../../../../../move-stdlib/docs/FixedPoint32.md#0x1_FixedPoint32">FixedPoint32</a> {
    <b>global</b>&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>&lt;CoinType&gt;&gt;(@<a href="Diem.md#0x1_Diem_CurrencyInfo">CurrencyInfo</a>).to_xdx_exchange_rate
}
</code></pre>


Checks whether the currency has a mint capability.  This is only relevant for
SCS coins


<a name="0x1_Diem_spec_has_mint_capability"></a>


<pre><code><b>fun</b> <a href="Diem.md#0x1_Diem_spec_has_mint_capability">spec_has_mint_capability</a>&lt;CoinType&gt;(addr: address): bool {
    <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_MintCapability">MintCapability</a>&lt;CoinType&gt;&gt;(addr)
}
</code></pre>


Returns true if a BurnCapability for CoinType exists at addr.


<a name="0x1_Diem_spec_has_burn_capability"></a>


<pre><code><b>fun</b> <a href="Diem.md#0x1_Diem_spec_has_burn_capability">spec_has_burn_capability</a>&lt;CoinType&gt;(addr: address): bool {
    <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_BurnCapability">BurnCapability</a>&lt;CoinType&gt;&gt;(addr)
}
</code></pre>


Returns the Preburn in the preburn queue.


<a name="0x1_Diem_spec_make_preburn"></a>


<pre><code><b>fun</b> <a href="Diem.md#0x1_Diem_spec_make_preburn">spec_make_preburn</a>&lt;CoinType&gt;(amount: u64): <a href="Diem.md#0x1_Diem_Preburn">Preburn</a>&lt;CoinType&gt; {
    <a href="Diem.md#0x1_Diem_Preburn">Preburn</a> { to_burn: <a href="Diem.md#0x1_Diem">Diem</a> { value: amount }}
}
</code></pre>


[//]: # ("File containing references which can be used from documentation")
[ACCESS_CONTROL]: https://github.com/diem/dip/blob/main/dips/dip-2.md
[ROLE]: https://github.com/diem/dip/blob/main/dips/dip-2.md#roles
[PERMISSION]: https://github.com/diem/dip/blob/main/dips/dip-2.md#permissions
