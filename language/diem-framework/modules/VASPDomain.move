/// Module managing VASP domains.
module DiemFramework::VASPDomain {
    use DiemFramework::Roles;
    use Std::Errors;
    use Std::Event::{Self, EventHandle};
    use Std::Signer;
    use Std::Vector;
    friend DiemFramework::DiemAccount;
    friend DiemFramework::AccountAdministrationScripts;

    /// This resource holds an entity's domain names.
    struct VASPDomains has key {
        /// The list of domain names owned by this parent vasp account
        domains: vector<VASPDomain>,
    }
    spec VASPDomains {
        /// All `VASPDomain`s stored in the `VASPDomains` resource are no more than 63 characters long.
        invariant forall i in 0..len(domains): len(domains[i].domain) <= DOMAIN_LENGTH;
        /// The list of `VASPDomain`s are a set
        invariant forall i in 0..len(domains):
        forall j in i + 1..len(domains): domains[i] != domains[j];
    }

    /// Struct to store the limit on-chain
    struct VASPDomain has drop, store, copy {
        domain: vector<u8>, // UTF-8 encoded and 63 characters
    }
    spec VASPDomain {
    /// All `VASPDomain`s must be no more than 63 characters long.
    invariant len(domain) <= DOMAIN_LENGTH;
    }

    struct VASPDomainManager has key {
        /// Event handle for `domains` added or removed events. Emitted every time a domain is added
        /// or removed to `domains`
        vasp_domain_events: EventHandle<VASPDomainEvent>,
    }

    struct VASPDomainEvent has drop, store {
        /// Whether a domain was added or removed
        removed: bool,
        /// VASP Domain string of the account
        domain: VASPDomain,
        /// On-chain account address
        address: address,
    }

    const DOMAIN_LENGTH: u64 = 63;

    // Error codes
    /// VASPDomains resource is not or already published.
    const EVASP_DOMAINS: u64 = 0;
    /// VASPDomainManager resource is not or already published.
    const EVASP_DOMAIN_MANAGER: u64 = 1;
    /// VASP domain was not found
    const EVASP_DOMAIN_NOT_FOUND: u64 = 2;
    /// VASP domain already exists
    const EVASP_DOMAIN_ALREADY_EXISTS: u64 = 3;
    /// VASPDomains resource was not published for a VASP account
    const EVASP_DOMAINS_NOT_PUBLISHED: u64 = 4;
    /// Invalid domain for VASPDomain
    const EINVALID_VASP_DOMAIN: u64 = 5;

    fun create_vasp_domain(domain: vector<u8>): VASPDomain {
        assert(Vector::length(&domain) <= DOMAIN_LENGTH, Errors::invalid_argument(EINVALID_VASP_DOMAIN));
        VASPDomain{ domain }
    }
    spec create_vasp_domain {
        include CreateVASPDomainAbortsIf;
        ensures result == VASPDomain { domain };
    }
    spec schema CreateVASPDomainAbortsIf {
        domain: vector<u8>;
        aborts_if Vector::length(domain) > DOMAIN_LENGTH with Errors::INVALID_ARGUMENT;
    }

    /// Publish a `VASPDomains` resource under `created` with an empty `domains`.
    /// Before VASP Domains, the Treasury Compliance account must send
    /// a transaction that invokes `add_vasp_domain` to set the `domains` field with a valid domain
    public(friend) fun publish_vasp_domains(
        vasp_account: &signer,
    ) {
        Roles::assert_parent_vasp_role(vasp_account);
        assert(
            !exists<VASPDomains>(Signer::address_of(vasp_account)),
            Errors::already_published(EVASP_DOMAINS)
        );
        move_to(vasp_account, VASPDomains {
            domains: Vector::empty(),
        })
    }
    spec publish_vasp_domains {
        let vasp_addr = Signer::spec_address_of(vasp_account);
        include Roles::AbortsIfNotParentVasp{account: vasp_account};
        include PublishVASPDomainsAbortsIf;
        include PublishVASPDomainsEnsures;
    }
    spec schema PublishVASPDomainsAbortsIf {
        vasp_addr: address;
        aborts_if has_vasp_domains(vasp_addr) with Errors::ALREADY_PUBLISHED;
    }
    spec schema PublishVASPDomainsEnsures {
        vasp_addr: address;
        ensures exists<VASPDomains>(vasp_addr);
        ensures Vector::is_empty(global<VASPDomains>(vasp_addr).domains);
    }

    public fun has_vasp_domains(addr: address): bool {
        exists<VASPDomains>(addr)
    }
    spec has_vasp_domains {
        aborts_if false;
        ensures result == exists<VASPDomains>(addr);
    }

    /// Publish a `VASPDomainManager` resource under `tc_account` with an empty `vasp_domain_events`.
    /// When Treasury Compliance account sends a transaction that invokes either `add_vasp_domain` or
    /// `remove_vasp_domain`, a `VASPDomainEvent` is emitted and added to `vasp_domain_events`.
    public(friend) fun publish_vasp_domain_manager(
        tc_account : &signer,
    ) {
        Roles::assert_treasury_compliance(tc_account);
        assert(
            !exists<VASPDomainManager>(Signer::address_of(tc_account)),
            Errors::already_published(EVASP_DOMAIN_MANAGER)
        );
        move_to(
            tc_account,
            VASPDomainManager {
                vasp_domain_events: Event::new_event_handle<VASPDomainEvent>(tc_account),
            }
        );
    }
    spec publish_vasp_domain_manager {
        include Roles::AbortsIfNotTreasuryCompliance{account: tc_account};
        aborts_if tc_domain_manager_exists() with Errors::ALREADY_PUBLISHED;
        ensures exists<VASPDomainManager>(Signer::spec_address_of(tc_account));
        modifies global<VASPDomainManager>(Signer::spec_address_of(tc_account));
    }

    /// Add a VASPDomain to a parent VASP's VASPDomains resource.
    /// When updating VASPDomains, a simple duplicate domain check is done.
    /// However, since domains are case insensitive, it is possible by error that two same domains in
    /// different lowercase and uppercase format gets added.
    public fun add_vasp_domain(
        tc_account: &signer,
        address: address,
        domain: vector<u8>,
    ) acquires VASPDomainManager, VASPDomains {
        Roles::assert_treasury_compliance(tc_account);
        assert(tc_domain_manager_exists(), Errors::not_published(EVASP_DOMAIN_MANAGER));
        assert(
            exists<VASPDomains>(address),
            Errors::not_published(EVASP_DOMAINS_NOT_PUBLISHED)
        );

        let account_domains = borrow_global_mut<VASPDomains>(address);
        let vasp_domain = create_vasp_domain(domain);

        assert(
            !Vector::contains(&account_domains.domains, &vasp_domain),
            Errors::invalid_argument(EVASP_DOMAIN_ALREADY_EXISTS)
        );

        Vector::push_back(&mut account_domains.domains, copy vasp_domain);

        Event::emit_event(
            &mut borrow_global_mut<VASPDomainManager>(@TreasuryCompliance).vasp_domain_events,
            VASPDomainEvent {
                removed: false,
                domain: vasp_domain,
                address,
            },
        );
    }
    spec add_vasp_domain {
        include AddVASPDomainAbortsIf;
        include AddVASPDomainEnsures;
        include AddVASPDomainEmits;
    }
    spec schema AddVASPDomainAbortsIf {
        tc_account: signer;
        address: address;
        domain: vector<u8>;
        let domains = global<VASPDomains>(address).domains;
        include Roles::AbortsIfNotTreasuryCompliance{account: tc_account};
        include CreateVASPDomainAbortsIf;
        aborts_if !exists<VASPDomains>(address) with Errors::NOT_PUBLISHED;
        aborts_if !tc_domain_manager_exists() with Errors::NOT_PUBLISHED;
        aborts_if contains(domains, VASPDomain { domain }) with Errors::INVALID_ARGUMENT;
    }
    spec schema AddVASPDomainEnsures {
        address: address;
        domain: vector<u8>;
        let post domains = global<VASPDomains>(address).domains;
        ensures contains(domains, VASPDomain { domain });
    }
    spec schema AddVASPDomainEmits {
        address: address;
        domain: vector<u8>;
        let handle = global<VASPDomainManager>(@TreasuryCompliance).vasp_domain_events;
        let msg = VASPDomainEvent {
            removed: false,
            domain: VASPDomain { domain },
            address,
        };
        emits msg to handle;
    }

    /// Remove a VASPDomain from a parent VASP's VASPDomains resource.
    public fun remove_vasp_domain(
        tc_account: &signer,
        address: address,
        domain: vector<u8>,
    ) acquires VASPDomainManager, VASPDomains {
        Roles::assert_treasury_compliance(tc_account);
        assert(tc_domain_manager_exists(), Errors::not_published(EVASP_DOMAIN_MANAGER));
        assert(
            exists<VASPDomains>(address),
            Errors::not_published(EVASP_DOMAINS_NOT_PUBLISHED)
        );

        let account_domains = borrow_global_mut<VASPDomains>(address);
        let vasp_domain = create_vasp_domain(domain);

        let (has, index) = Vector::index_of(&account_domains.domains, &vasp_domain);
        if (has) {
            Vector::remove(&mut account_domains.domains, index);
        } else {
            abort Errors::invalid_argument(EVASP_DOMAIN_NOT_FOUND)
        };

        Event::emit_event(
            &mut borrow_global_mut<VASPDomainManager>(@TreasuryCompliance).vasp_domain_events,
            VASPDomainEvent {
                removed: true,
                domain: vasp_domain,
                address: address,
            },
        );
    }
    spec remove_vasp_domain {
        include RemoveVASPDomainAbortsIf;
        include RemoveVASPDomainEnsures;
        include RemoveVASPDomainEmits;
    }
    spec schema RemoveVASPDomainAbortsIf {
        tc_account: signer;
        address: address;
        domain: vector<u8>;
        let domains = global<VASPDomains>(address).domains;
        include Roles::AbortsIfNotTreasuryCompliance{account: tc_account};
        include CreateVASPDomainAbortsIf;
        aborts_if !exists<VASPDomains>(address) with Errors::NOT_PUBLISHED;
        aborts_if !tc_domain_manager_exists() with Errors::NOT_PUBLISHED;
        aborts_if !contains(domains, VASPDomain { domain }) with Errors::INVALID_ARGUMENT;
    }
    spec schema RemoveVASPDomainEnsures {
        address: address;
        domain: vector<u8>;
        let post domains = global<VASPDomains>(address).domains;
        ensures !contains(domains, VASPDomain { domain });
    }
    spec schema RemoveVASPDomainEmits {
        tc_account: signer;
        address: address;
        domain: vector<u8>;
        let handle = global<VASPDomainManager>(@TreasuryCompliance).vasp_domain_events;
        let msg = VASPDomainEvent {
            removed: true,
            domain: VASPDomain { domain },
            address,
        };
        emits msg to handle;
    }

    public fun has_vasp_domain(addr: address, domain: vector<u8>): bool acquires VASPDomains {
        assert(
            exists<VASPDomains>(addr),
            Errors::not_published(EVASP_DOMAINS_NOT_PUBLISHED)
        );
        let account_domains = borrow_global<VASPDomains>(addr);
        let vasp_domain = create_vasp_domain(domain);
        Vector::contains(&account_domains.domains, &vasp_domain)
    }
    spec has_vasp_domain {
        include HasVASPDomainAbortsIf;
        let id_domain = VASPDomain { domain };
        ensures result == contains(global<VASPDomains>(addr).domains, id_domain);
    }
    spec schema HasVASPDomainAbortsIf {
        addr: address;
        domain: vector<u8>;
        include CreateVASPDomainAbortsIf;
        aborts_if !exists<VASPDomains>(addr) with Errors::NOT_PUBLISHED;
    }

    public fun tc_domain_manager_exists(): bool {
        exists<VASPDomainManager>(@TreasuryCompliance)
    }
    spec tc_domain_manager_exists {
        aborts_if false;
        ensures result == exists<VASPDomainManager>(@TreasuryCompliance);
    }
}
