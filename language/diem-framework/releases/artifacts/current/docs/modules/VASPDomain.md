
<a name="0x1_VASPDomain"></a>

# Module `0x1::VASPDomain`

Module managing VASP domains.


-  [Resource `VASPDomains`](#0x1_VASPDomain_VASPDomains)
-  [Struct `VASPDomain`](#0x1_VASPDomain_VASPDomain)
-  [Resource `VASPDomainManager`](#0x1_VASPDomain_VASPDomainManager)
-  [Struct `VASPDomainEvent`](#0x1_VASPDomain_VASPDomainEvent)
-  [Constants](#@Constants_0)
-  [Function `create_vasp_domain`](#0x1_VASPDomain_create_vasp_domain)
-  [Function `publish_vasp_domains`](#0x1_VASPDomain_publish_vasp_domains)
-  [Function `has_vasp_domains`](#0x1_VASPDomain_has_vasp_domains)
-  [Function `publish_vasp_domain_manager`](#0x1_VASPDomain_publish_vasp_domain_manager)
-  [Function `add_vasp_domain`](#0x1_VASPDomain_add_vasp_domain)
-  [Function `remove_vasp_domain`](#0x1_VASPDomain_remove_vasp_domain)
-  [Function `has_vasp_domain`](#0x1_VASPDomain_has_vasp_domain)
-  [Function `tc_domain_manager_exists`](#0x1_VASPDomain_tc_domain_manager_exists)


<pre><code><b>use</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors">0x1::Errors</a>;
<b>use</b> <a href="../../../../../../move-stdlib/docs/Event.md#0x1_Event">0x1::Event</a>;
<b>use</b> <a href="Roles.md#0x1_Roles">0x1::Roles</a>;
<b>use</b> <a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer">0x1::Signer</a>;
<b>use</b> <a href="../../../../../../move-stdlib/docs/Vector.md#0x1_Vector">0x1::Vector</a>;
</code></pre>



<a name="0x1_VASPDomain_VASPDomains"></a>

## Resource `VASPDomains`

This resource holds an entity's domain names.


<pre><code><b>struct</b> <a href="VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomains</a> has key
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>domains: vector&lt;<a href="VASPDomain.md#0x1_VASPDomain_VASPDomain">VASPDomain::VASPDomain</a>&gt;</code>
</dt>
<dd>
 The list of domain names owned by this parent vasp account
</dd>
</dl>


</details>

<details>
<summary>Specification</summary>


All <code><a href="VASPDomain.md#0x1_VASPDomain">VASPDomain</a></code>s stored in the <code><a href="VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomains</a></code> resource are no more than 63 characters long.


<pre><code><b>invariant</b> <b>forall</b> i in 0..len(domains): len(domains[i].domain) &lt;= <a href="VASPDomain.md#0x1_VASPDomain_DOMAIN_LENGTH">DOMAIN_LENGTH</a>;
</code></pre>


The list of <code><a href="VASPDomain.md#0x1_VASPDomain">VASPDomain</a></code>s are a set


<pre><code><b>invariant</b> <b>forall</b> i in 0..len(domains):
<b>forall</b> j in i + 1..len(domains): domains[i] != domains[j];
</code></pre>



</details>

<a name="0x1_VASPDomain_VASPDomain"></a>

## Struct `VASPDomain`

Struct to store the limit on-chain


<pre><code><b>struct</b> <a href="VASPDomain.md#0x1_VASPDomain">VASPDomain</a> has <b>copy</b>, drop, store
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>domain: vector&lt;u8&gt;</code>
</dt>
<dd>

</dd>
</dl>


</details>

<details>
<summary>Specification</summary>


All <code><a href="VASPDomain.md#0x1_VASPDomain">VASPDomain</a></code>s must be no more than 63 characters long.


<pre><code><b>invariant</b> len(domain) &lt;= <a href="VASPDomain.md#0x1_VASPDomain_DOMAIN_LENGTH">DOMAIN_LENGTH</a>;
</code></pre>



</details>

<a name="0x1_VASPDomain_VASPDomainManager"></a>

## Resource `VASPDomainManager`



<pre><code><b>struct</b> <a href="VASPDomain.md#0x1_VASPDomain_VASPDomainManager">VASPDomainManager</a> has key
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>vasp_domain_events: <a href="../../../../../../move-stdlib/docs/Event.md#0x1_Event_EventHandle">Event::EventHandle</a>&lt;<a href="VASPDomain.md#0x1_VASPDomain_VASPDomainEvent">VASPDomain::VASPDomainEvent</a>&gt;</code>
</dt>
<dd>
 Event handle for <code>domains</code> added or removed events. Emitted every time a domain is added
 or removed to <code>domains</code>
</dd>
</dl>


</details>

<a name="0x1_VASPDomain_VASPDomainEvent"></a>

## Struct `VASPDomainEvent`



<pre><code><b>struct</b> <a href="VASPDomain.md#0x1_VASPDomain_VASPDomainEvent">VASPDomainEvent</a> has drop, store
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>removed: bool</code>
</dt>
<dd>
 Whether a domain was added or removed
</dd>
<dt>
<code>domain: <a href="VASPDomain.md#0x1_VASPDomain_VASPDomain">VASPDomain::VASPDomain</a></code>
</dt>
<dd>
 VASP Domain string of the account
</dd>
<dt>
<code>address: address</code>
</dt>
<dd>
 On-chain account address
</dd>
</dl>


</details>

<a name="@Constants_0"></a>

## Constants


<a name="0x1_VASPDomain_DOMAIN_LENGTH"></a>



<pre><code><b>const</b> <a href="VASPDomain.md#0x1_VASPDomain_DOMAIN_LENGTH">DOMAIN_LENGTH</a>: u64 = 63;
</code></pre>



<a name="0x1_VASPDomain_EINVALID_VASP_DOMAIN"></a>

Invalid domain for VASPDomain


<pre><code><b>const</b> <a href="VASPDomain.md#0x1_VASPDomain_EINVALID_VASP_DOMAIN">EINVALID_VASP_DOMAIN</a>: u64 = 5;
</code></pre>



<a name="0x1_VASPDomain_EVASP_DOMAINS"></a>

VASPDomains resource is not or already published.


<pre><code><b>const</b> <a href="VASPDomain.md#0x1_VASPDomain_EVASP_DOMAINS">EVASP_DOMAINS</a>: u64 = 0;
</code></pre>



<a name="0x1_VASPDomain_EVASP_DOMAINS_NOT_PUBLISHED"></a>

VASPDomains resource was not published for a VASP account


<pre><code><b>const</b> <a href="VASPDomain.md#0x1_VASPDomain_EVASP_DOMAINS_NOT_PUBLISHED">EVASP_DOMAINS_NOT_PUBLISHED</a>: u64 = 4;
</code></pre>



<a name="0x1_VASPDomain_EVASP_DOMAIN_ALREADY_EXISTS"></a>

VASP domain already exists


<pre><code><b>const</b> <a href="VASPDomain.md#0x1_VASPDomain_EVASP_DOMAIN_ALREADY_EXISTS">EVASP_DOMAIN_ALREADY_EXISTS</a>: u64 = 3;
</code></pre>



<a name="0x1_VASPDomain_EVASP_DOMAIN_MANAGER"></a>

VASPDomainManager resource is not or already published.


<pre><code><b>const</b> <a href="VASPDomain.md#0x1_VASPDomain_EVASP_DOMAIN_MANAGER">EVASP_DOMAIN_MANAGER</a>: u64 = 1;
</code></pre>



<a name="0x1_VASPDomain_EVASP_DOMAIN_NOT_FOUND"></a>

VASP domain was not found


<pre><code><b>const</b> <a href="VASPDomain.md#0x1_VASPDomain_EVASP_DOMAIN_NOT_FOUND">EVASP_DOMAIN_NOT_FOUND</a>: u64 = 2;
</code></pre>



<a name="0x1_VASPDomain_create_vasp_domain"></a>

## Function `create_vasp_domain`



<pre><code><b>fun</b> <a href="VASPDomain.md#0x1_VASPDomain_create_vasp_domain">create_vasp_domain</a>(domain: vector&lt;u8&gt;): <a href="VASPDomain.md#0x1_VASPDomain_VASPDomain">VASPDomain::VASPDomain</a>
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>fun</b> <a href="VASPDomain.md#0x1_VASPDomain_create_vasp_domain">create_vasp_domain</a>(domain: vector&lt;u8&gt;): <a href="VASPDomain.md#0x1_VASPDomain">VASPDomain</a> {
    <b>assert</b>(<a href="../../../../../../move-stdlib/docs/Vector.md#0x1_Vector_length">Vector::length</a>(&domain) &lt;= <a href="VASPDomain.md#0x1_VASPDomain_DOMAIN_LENGTH">DOMAIN_LENGTH</a>, <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_invalid_argument">Errors::invalid_argument</a>(<a href="VASPDomain.md#0x1_VASPDomain_EINVALID_VASP_DOMAIN">EINVALID_VASP_DOMAIN</a>));
    <a href="VASPDomain.md#0x1_VASPDomain">VASPDomain</a>{ domain }
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="VASPDomain.md#0x1_VASPDomain_CreateVASPDomainAbortsIf">CreateVASPDomainAbortsIf</a>;
<b>ensures</b> result == <a href="VASPDomain.md#0x1_VASPDomain">VASPDomain</a> { domain };
</code></pre>




<a name="0x1_VASPDomain_CreateVASPDomainAbortsIf"></a>


<pre><code><b>schema</b> <a href="VASPDomain.md#0x1_VASPDomain_CreateVASPDomainAbortsIf">CreateVASPDomainAbortsIf</a> {
    domain: vector&lt;u8&gt;;
    <b>aborts_if</b> <a href="../../../../../../move-stdlib/docs/Vector.md#0x1_Vector_length">Vector::length</a>(domain) &gt; <a href="VASPDomain.md#0x1_VASPDomain_DOMAIN_LENGTH">DOMAIN_LENGTH</a> <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>;
}
</code></pre>



</details>

<a name="0x1_VASPDomain_publish_vasp_domains"></a>

## Function `publish_vasp_domains`

Publish a <code><a href="VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomains</a></code> resource under <code>created</code> with an empty <code>domains</code>.
Before VASP Domains, the Treasury Compliance account must send
a transaction that invokes <code>add_vasp_domain</code> to set the <code>domains</code> field with a valid domain


<pre><code><b>public</b>(<b>friend</b>) <b>fun</b> <a href="VASPDomain.md#0x1_VASPDomain_publish_vasp_domains">publish_vasp_domains</a>(vasp_account: &signer)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>friend</b>) <b>fun</b> <a href="VASPDomain.md#0x1_VASPDomain_publish_vasp_domains">publish_vasp_domains</a>(
    vasp_account: &signer,
) {
    <a href="Roles.md#0x1_Roles_assert_parent_vasp_role">Roles::assert_parent_vasp_role</a>(vasp_account);
    <b>assert</b>(
        !<b>exists</b>&lt;<a href="VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomains</a>&gt;(<a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_address_of">Signer::address_of</a>(vasp_account)),
        <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_already_published">Errors::already_published</a>(<a href="VASPDomain.md#0x1_VASPDomain_EVASP_DOMAINS">EVASP_DOMAINS</a>)
    );
    move_to(vasp_account, <a href="VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomains</a> {
        domains: <a href="../../../../../../move-stdlib/docs/Vector.md#0x1_Vector_empty">Vector::empty</a>(),
    })
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>let</b> vasp_addr = <a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(vasp_account);
<b>include</b> <a href="Roles.md#0x1_Roles_AbortsIfNotParentVasp">Roles::AbortsIfNotParentVasp</a>{account: vasp_account};
<b>include</b> <a href="VASPDomain.md#0x1_VASPDomain_PublishVASPDomainsAbortsIf">PublishVASPDomainsAbortsIf</a>;
<b>include</b> <a href="VASPDomain.md#0x1_VASPDomain_PublishVASPDomainsEnsures">PublishVASPDomainsEnsures</a>;
</code></pre>




<a name="0x1_VASPDomain_PublishVASPDomainsAbortsIf"></a>


<pre><code><b>schema</b> <a href="VASPDomain.md#0x1_VASPDomain_PublishVASPDomainsAbortsIf">PublishVASPDomainsAbortsIf</a> {
    vasp_addr: address;
    <b>aborts_if</b> <a href="VASPDomain.md#0x1_VASPDomain_has_vasp_domains">has_vasp_domains</a>(vasp_addr) <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a>;
}
</code></pre>




<a name="0x1_VASPDomain_PublishVASPDomainsEnsures"></a>


<pre><code><b>schema</b> <a href="VASPDomain.md#0x1_VASPDomain_PublishVASPDomainsEnsures">PublishVASPDomainsEnsures</a> {
    vasp_addr: address;
    <b>ensures</b> <b>exists</b>&lt;<a href="VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomains</a>&gt;(vasp_addr);
    <b>ensures</b> <a href="../../../../../../move-stdlib/docs/Vector.md#0x1_Vector_is_empty">Vector::is_empty</a>(<b>global</b>&lt;<a href="VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomains</a>&gt;(vasp_addr).domains);
}
</code></pre>



</details>

<a name="0x1_VASPDomain_has_vasp_domains"></a>

## Function `has_vasp_domains`



<pre><code><b>public</b> <b>fun</b> <a href="VASPDomain.md#0x1_VASPDomain_has_vasp_domains">has_vasp_domains</a>(addr: address): bool
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="VASPDomain.md#0x1_VASPDomain_has_vasp_domains">has_vasp_domains</a>(addr: address): bool {
    <b>exists</b>&lt;<a href="VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomains</a>&gt;(addr)
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>aborts_if</b> <b>false</b>;
<b>ensures</b> result == <b>exists</b>&lt;<a href="VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomains</a>&gt;(addr);
</code></pre>



</details>

<a name="0x1_VASPDomain_publish_vasp_domain_manager"></a>

## Function `publish_vasp_domain_manager`

Publish a <code><a href="VASPDomain.md#0x1_VASPDomain_VASPDomainManager">VASPDomainManager</a></code> resource under <code>tc_account</code> with an empty <code>vasp_domain_events</code>.
When Treasury Compliance account sends a transaction that invokes either <code>add_vasp_domain</code> or
<code>remove_vasp_domain</code>, a <code><a href="VASPDomain.md#0x1_VASPDomain_VASPDomainEvent">VASPDomainEvent</a></code> is emitted and added to <code>vasp_domain_events</code>.


<pre><code><b>public</b>(<b>friend</b>) <b>fun</b> <a href="VASPDomain.md#0x1_VASPDomain_publish_vasp_domain_manager">publish_vasp_domain_manager</a>(tc_account: &signer)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>friend</b>) <b>fun</b> <a href="VASPDomain.md#0x1_VASPDomain_publish_vasp_domain_manager">publish_vasp_domain_manager</a>(
    tc_account : &signer,
) {
    <a href="Roles.md#0x1_Roles_assert_treasury_compliance">Roles::assert_treasury_compliance</a>(tc_account);
    <b>assert</b>(
        !<b>exists</b>&lt;<a href="VASPDomain.md#0x1_VASPDomain_VASPDomainManager">VASPDomainManager</a>&gt;(<a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_address_of">Signer::address_of</a>(tc_account)),
        <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_already_published">Errors::already_published</a>(<a href="VASPDomain.md#0x1_VASPDomain_EVASP_DOMAIN_MANAGER">EVASP_DOMAIN_MANAGER</a>)
    );
    move_to(
        tc_account,
        <a href="VASPDomain.md#0x1_VASPDomain_VASPDomainManager">VASPDomainManager</a> {
            vasp_domain_events: <a href="../../../../../../move-stdlib/docs/Event.md#0x1_Event_new_event_handle">Event::new_event_handle</a>&lt;<a href="VASPDomain.md#0x1_VASPDomain_VASPDomainEvent">VASPDomainEvent</a>&gt;(tc_account),
        }
    );
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="Roles.md#0x1_Roles_AbortsIfNotTreasuryCompliance">Roles::AbortsIfNotTreasuryCompliance</a>{account: tc_account};
<b>aborts_if</b> <a href="VASPDomain.md#0x1_VASPDomain_tc_domain_manager_exists">tc_domain_manager_exists</a>() <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a>;
<b>ensures</b> <b>exists</b>&lt;<a href="VASPDomain.md#0x1_VASPDomain_VASPDomainManager">VASPDomainManager</a>&gt;(<a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(tc_account));
<b>modifies</b> <b>global</b>&lt;<a href="VASPDomain.md#0x1_VASPDomain_VASPDomainManager">VASPDomainManager</a>&gt;(<a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(tc_account));
</code></pre>



</details>

<a name="0x1_VASPDomain_add_vasp_domain"></a>

## Function `add_vasp_domain`

Add a VASPDomain to a parent VASP's VASPDomains resource.
When updating VASPDomains, a simple duplicate domain check is done.
However, since domains are case insensitive, it is possible by error that two same domains in
different lowercase and uppercase format gets added.


<pre><code><b>public</b> <b>fun</b> <a href="VASPDomain.md#0x1_VASPDomain_add_vasp_domain">add_vasp_domain</a>(tc_account: &signer, address: address, domain: vector&lt;u8&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="VASPDomain.md#0x1_VASPDomain_add_vasp_domain">add_vasp_domain</a>(
    tc_account: &signer,
    address: address,
    domain: vector&lt;u8&gt;,
) <b>acquires</b> <a href="VASPDomain.md#0x1_VASPDomain_VASPDomainManager">VASPDomainManager</a>, <a href="VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomains</a> {
    <a href="Roles.md#0x1_Roles_assert_treasury_compliance">Roles::assert_treasury_compliance</a>(tc_account);
    <b>assert</b>(<a href="VASPDomain.md#0x1_VASPDomain_tc_domain_manager_exists">tc_domain_manager_exists</a>(), <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_not_published">Errors::not_published</a>(<a href="VASPDomain.md#0x1_VASPDomain_EVASP_DOMAIN_MANAGER">EVASP_DOMAIN_MANAGER</a>));
    <b>assert</b>(
        <b>exists</b>&lt;<a href="VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomains</a>&gt;(address),
        <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_not_published">Errors::not_published</a>(<a href="VASPDomain.md#0x1_VASPDomain_EVASP_DOMAINS_NOT_PUBLISHED">EVASP_DOMAINS_NOT_PUBLISHED</a>)
    );

    <b>let</b> account_domains = borrow_global_mut&lt;<a href="VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomains</a>&gt;(address);
    <b>let</b> vasp_domain = <a href="VASPDomain.md#0x1_VASPDomain_create_vasp_domain">create_vasp_domain</a>(domain);

    <b>assert</b>(
        !<a href="../../../../../../move-stdlib/docs/Vector.md#0x1_Vector_contains">Vector::contains</a>(&account_domains.domains, &vasp_domain),
        <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_invalid_argument">Errors::invalid_argument</a>(<a href="VASPDomain.md#0x1_VASPDomain_EVASP_DOMAIN_ALREADY_EXISTS">EVASP_DOMAIN_ALREADY_EXISTS</a>)
    );

    <a href="../../../../../../move-stdlib/docs/Vector.md#0x1_Vector_push_back">Vector::push_back</a>(&<b>mut</b> account_domains.domains, <b>copy</b> vasp_domain);

    <a href="../../../../../../move-stdlib/docs/Event.md#0x1_Event_emit_event">Event::emit_event</a>(
        &<b>mut</b> borrow_global_mut&lt;<a href="VASPDomain.md#0x1_VASPDomain_VASPDomainManager">VASPDomainManager</a>&gt;(@TreasuryCompliance).vasp_domain_events,
        <a href="VASPDomain.md#0x1_VASPDomain_VASPDomainEvent">VASPDomainEvent</a> {
            removed: <b>false</b>,
            domain: vasp_domain,
            address,
        },
    );
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="VASPDomain.md#0x1_VASPDomain_AddVASPDomainAbortsIf">AddVASPDomainAbortsIf</a>;
<b>include</b> <a href="VASPDomain.md#0x1_VASPDomain_AddVASPDomainEnsures">AddVASPDomainEnsures</a>;
<b>include</b> <a href="VASPDomain.md#0x1_VASPDomain_AddVASPDomainEmits">AddVASPDomainEmits</a>;
</code></pre>




<a name="0x1_VASPDomain_AddVASPDomainAbortsIf"></a>


<pre><code><b>schema</b> <a href="VASPDomain.md#0x1_VASPDomain_AddVASPDomainAbortsIf">AddVASPDomainAbortsIf</a> {
    tc_account: signer;
    address: address;
    domain: vector&lt;u8&gt;;
    <b>let</b> domains = <b>global</b>&lt;<a href="VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomains</a>&gt;(address).domains;
    <b>include</b> <a href="Roles.md#0x1_Roles_AbortsIfNotTreasuryCompliance">Roles::AbortsIfNotTreasuryCompliance</a>{account: tc_account};
    <b>include</b> <a href="VASPDomain.md#0x1_VASPDomain_CreateVASPDomainAbortsIf">CreateVASPDomainAbortsIf</a>;
    <b>aborts_if</b> !<b>exists</b>&lt;<a href="VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomains</a>&gt;(address) <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>;
    <b>aborts_if</b> !<a href="VASPDomain.md#0x1_VASPDomain_tc_domain_manager_exists">tc_domain_manager_exists</a>() <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>;
    <b>aborts_if</b> contains(domains, <a href="VASPDomain.md#0x1_VASPDomain">VASPDomain</a> { domain }) <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>;
}
</code></pre>




<a name="0x1_VASPDomain_AddVASPDomainEnsures"></a>


<pre><code><b>schema</b> <a href="VASPDomain.md#0x1_VASPDomain_AddVASPDomainEnsures">AddVASPDomainEnsures</a> {
    address: address;
    domain: vector&lt;u8&gt;;
    <b>let</b> post domains = <b>global</b>&lt;<a href="VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomains</a>&gt;(address).domains;
    <b>ensures</b> contains(domains, <a href="VASPDomain.md#0x1_VASPDomain">VASPDomain</a> { domain });
}
</code></pre>




<a name="0x1_VASPDomain_AddVASPDomainEmits"></a>


<pre><code><b>schema</b> <a href="VASPDomain.md#0x1_VASPDomain_AddVASPDomainEmits">AddVASPDomainEmits</a> {
    address: address;
    domain: vector&lt;u8&gt;;
    <b>let</b> handle = <b>global</b>&lt;<a href="VASPDomain.md#0x1_VASPDomain_VASPDomainManager">VASPDomainManager</a>&gt;(@TreasuryCompliance).vasp_domain_events;
    <b>let</b> msg = <a href="VASPDomain.md#0x1_VASPDomain_VASPDomainEvent">VASPDomainEvent</a> {
        removed: <b>false</b>,
        domain: <a href="VASPDomain.md#0x1_VASPDomain">VASPDomain</a> { domain },
        address,
    };
    emits msg <b>to</b> handle;
}
</code></pre>



</details>

<a name="0x1_VASPDomain_remove_vasp_domain"></a>

## Function `remove_vasp_domain`

Remove a VASPDomain from a parent VASP's VASPDomains resource.


<pre><code><b>public</b> <b>fun</b> <a href="VASPDomain.md#0x1_VASPDomain_remove_vasp_domain">remove_vasp_domain</a>(tc_account: &signer, address: address, domain: vector&lt;u8&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="VASPDomain.md#0x1_VASPDomain_remove_vasp_domain">remove_vasp_domain</a>(
    tc_account: &signer,
    address: address,
    domain: vector&lt;u8&gt;,
) <b>acquires</b> <a href="VASPDomain.md#0x1_VASPDomain_VASPDomainManager">VASPDomainManager</a>, <a href="VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomains</a> {
    <a href="Roles.md#0x1_Roles_assert_treasury_compliance">Roles::assert_treasury_compliance</a>(tc_account);
    <b>assert</b>(<a href="VASPDomain.md#0x1_VASPDomain_tc_domain_manager_exists">tc_domain_manager_exists</a>(), <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_not_published">Errors::not_published</a>(<a href="VASPDomain.md#0x1_VASPDomain_EVASP_DOMAIN_MANAGER">EVASP_DOMAIN_MANAGER</a>));
    <b>assert</b>(
        <b>exists</b>&lt;<a href="VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomains</a>&gt;(address),
        <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_not_published">Errors::not_published</a>(<a href="VASPDomain.md#0x1_VASPDomain_EVASP_DOMAINS_NOT_PUBLISHED">EVASP_DOMAINS_NOT_PUBLISHED</a>)
    );

    <b>let</b> account_domains = borrow_global_mut&lt;<a href="VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomains</a>&gt;(address);
    <b>let</b> vasp_domain = <a href="VASPDomain.md#0x1_VASPDomain_create_vasp_domain">create_vasp_domain</a>(domain);

    <b>let</b> (has, index) = <a href="../../../../../../move-stdlib/docs/Vector.md#0x1_Vector_index_of">Vector::index_of</a>(&account_domains.domains, &vasp_domain);
    <b>if</b> (has) {
        <a href="../../../../../../move-stdlib/docs/Vector.md#0x1_Vector_remove">Vector::remove</a>(&<b>mut</b> account_domains.domains, index);
    } <b>else</b> {
        <b>abort</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_invalid_argument">Errors::invalid_argument</a>(<a href="VASPDomain.md#0x1_VASPDomain_EVASP_DOMAIN_NOT_FOUND">EVASP_DOMAIN_NOT_FOUND</a>)
    };

    <a href="../../../../../../move-stdlib/docs/Event.md#0x1_Event_emit_event">Event::emit_event</a>(
        &<b>mut</b> borrow_global_mut&lt;<a href="VASPDomain.md#0x1_VASPDomain_VASPDomainManager">VASPDomainManager</a>&gt;(@TreasuryCompliance).vasp_domain_events,
        <a href="VASPDomain.md#0x1_VASPDomain_VASPDomainEvent">VASPDomainEvent</a> {
            removed: <b>true</b>,
            domain: vasp_domain,
            address: address,
        },
    );
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="VASPDomain.md#0x1_VASPDomain_RemoveVASPDomainAbortsIf">RemoveVASPDomainAbortsIf</a>;
<b>include</b> <a href="VASPDomain.md#0x1_VASPDomain_RemoveVASPDomainEnsures">RemoveVASPDomainEnsures</a>;
<b>include</b> <a href="VASPDomain.md#0x1_VASPDomain_RemoveVASPDomainEmits">RemoveVASPDomainEmits</a>;
</code></pre>




<a name="0x1_VASPDomain_RemoveVASPDomainAbortsIf"></a>


<pre><code><b>schema</b> <a href="VASPDomain.md#0x1_VASPDomain_RemoveVASPDomainAbortsIf">RemoveVASPDomainAbortsIf</a> {
    tc_account: signer;
    address: address;
    domain: vector&lt;u8&gt;;
    <b>let</b> domains = <b>global</b>&lt;<a href="VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomains</a>&gt;(address).domains;
    <b>include</b> <a href="Roles.md#0x1_Roles_AbortsIfNotTreasuryCompliance">Roles::AbortsIfNotTreasuryCompliance</a>{account: tc_account};
    <b>include</b> <a href="VASPDomain.md#0x1_VASPDomain_CreateVASPDomainAbortsIf">CreateVASPDomainAbortsIf</a>;
    <b>aborts_if</b> !<b>exists</b>&lt;<a href="VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomains</a>&gt;(address) <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>;
    <b>aborts_if</b> !<a href="VASPDomain.md#0x1_VASPDomain_tc_domain_manager_exists">tc_domain_manager_exists</a>() <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>;
    <b>aborts_if</b> !contains(domains, <a href="VASPDomain.md#0x1_VASPDomain">VASPDomain</a> { domain }) <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>;
}
</code></pre>




<a name="0x1_VASPDomain_RemoveVASPDomainEnsures"></a>


<pre><code><b>schema</b> <a href="VASPDomain.md#0x1_VASPDomain_RemoveVASPDomainEnsures">RemoveVASPDomainEnsures</a> {
    address: address;
    domain: vector&lt;u8&gt;;
    <b>let</b> post domains = <b>global</b>&lt;<a href="VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomains</a>&gt;(address).domains;
    <b>ensures</b> !contains(domains, <a href="VASPDomain.md#0x1_VASPDomain">VASPDomain</a> { domain });
}
</code></pre>




<a name="0x1_VASPDomain_RemoveVASPDomainEmits"></a>


<pre><code><b>schema</b> <a href="VASPDomain.md#0x1_VASPDomain_RemoveVASPDomainEmits">RemoveVASPDomainEmits</a> {
    tc_account: signer;
    address: address;
    domain: vector&lt;u8&gt;;
    <b>let</b> handle = <b>global</b>&lt;<a href="VASPDomain.md#0x1_VASPDomain_VASPDomainManager">VASPDomainManager</a>&gt;(@TreasuryCompliance).vasp_domain_events;
    <b>let</b> msg = <a href="VASPDomain.md#0x1_VASPDomain_VASPDomainEvent">VASPDomainEvent</a> {
        removed: <b>true</b>,
        domain: <a href="VASPDomain.md#0x1_VASPDomain">VASPDomain</a> { domain },
        address,
    };
    emits msg <b>to</b> handle;
}
</code></pre>



</details>

<a name="0x1_VASPDomain_has_vasp_domain"></a>

## Function `has_vasp_domain`



<pre><code><b>public</b> <b>fun</b> <a href="VASPDomain.md#0x1_VASPDomain_has_vasp_domain">has_vasp_domain</a>(addr: address, domain: vector&lt;u8&gt;): bool
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="VASPDomain.md#0x1_VASPDomain_has_vasp_domain">has_vasp_domain</a>(addr: address, domain: vector&lt;u8&gt;): bool <b>acquires</b> <a href="VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomains</a> {
    <b>assert</b>(
        <b>exists</b>&lt;<a href="VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomains</a>&gt;(addr),
        <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_not_published">Errors::not_published</a>(<a href="VASPDomain.md#0x1_VASPDomain_EVASP_DOMAINS_NOT_PUBLISHED">EVASP_DOMAINS_NOT_PUBLISHED</a>)
    );
    <b>let</b> account_domains = borrow_global&lt;<a href="VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomains</a>&gt;(addr);
    <b>let</b> vasp_domain = <a href="VASPDomain.md#0x1_VASPDomain_create_vasp_domain">create_vasp_domain</a>(domain);
    <a href="../../../../../../move-stdlib/docs/Vector.md#0x1_Vector_contains">Vector::contains</a>(&account_domains.domains, &vasp_domain)
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="VASPDomain.md#0x1_VASPDomain_HasVASPDomainAbortsIf">HasVASPDomainAbortsIf</a>;
<b>let</b> id_domain = <a href="VASPDomain.md#0x1_VASPDomain">VASPDomain</a> { domain };
<b>ensures</b> result == contains(<b>global</b>&lt;<a href="VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomains</a>&gt;(addr).domains, id_domain);
</code></pre>




<a name="0x1_VASPDomain_HasVASPDomainAbortsIf"></a>


<pre><code><b>schema</b> <a href="VASPDomain.md#0x1_VASPDomain_HasVASPDomainAbortsIf">HasVASPDomainAbortsIf</a> {
    addr: address;
    domain: vector&lt;u8&gt;;
    <b>include</b> <a href="VASPDomain.md#0x1_VASPDomain_CreateVASPDomainAbortsIf">CreateVASPDomainAbortsIf</a>;
    <b>aborts_if</b> !<b>exists</b>&lt;<a href="VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomains</a>&gt;(addr) <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>;
}
</code></pre>



</details>

<a name="0x1_VASPDomain_tc_domain_manager_exists"></a>

## Function `tc_domain_manager_exists`



<pre><code><b>public</b> <b>fun</b> <a href="VASPDomain.md#0x1_VASPDomain_tc_domain_manager_exists">tc_domain_manager_exists</a>(): bool
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="VASPDomain.md#0x1_VASPDomain_tc_domain_manager_exists">tc_domain_manager_exists</a>(): bool {
    <b>exists</b>&lt;<a href="VASPDomain.md#0x1_VASPDomain_VASPDomainManager">VASPDomainManager</a>&gt;(@TreasuryCompliance)
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>aborts_if</b> <b>false</b>;
<b>ensures</b> result == <b>exists</b>&lt;<a href="VASPDomain.md#0x1_VASPDomain_VASPDomainManager">VASPDomainManager</a>&gt;(@TreasuryCompliance);
</code></pre>



</details>


[//]: # ("File containing references which can be used from documentation")
[ACCESS_CONTROL]: https://github.com/diem/dip/blob/main/dips/dip-2.md
[ROLE]: https://github.com/diem/dip/blob/main/dips/dip-2.md#roles
[PERMISSION]: https://github.com/diem/dip/blob/main/dips/dip-2.md#permissions
