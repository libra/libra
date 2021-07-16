/// This module defines role-based access control for the Diem framework.
///
/// Roles are associated with accounts and govern what operations are permitted by those accounts. A role
/// is typically asserted on function entry using a statement like `Self::assert_diem_root(account)`. This
/// module provides multiple assertion functions like this one, as well as the functions to setup roles.
///
/// For a conceptual discussion of roles, see the [DIP-2 document][ACCESS_CONTROL].
module DiemFramework::Roles {
    use DiemFramework::CoreAddresses;
    use DiemFramework::DiemTimestamp;
    use Std::Errors;
    use Std::Signer;
    friend DiemFramework::DiemAccount;

    /// A `RoleId` resource was in an unexpected state
    const EROLE_ID: u64 = 0;
    /// The signer didn't have the required Diem Root role
    const EDIEM_ROOT: u64 = 1;
    /// The signer didn't have the required Treasury & Compliance role
    const ETREASURY_COMPLIANCE: u64 = 2;
    /// The signer didn't have the required Parent VASP role
    const EPARENT_VASP: u64 = 3;
    /// The signer didn't have the required ParentVASP or ChildVASP role
    const EPARENT_VASP_OR_CHILD_VASP: u64 = 4;
    /// The signer didn't have the required Parent VASP or Designated Dealer role
    const EPARENT_VASP_OR_DESIGNATED_DEALER: u64 = 5;
    /// The signer didn't have the required Designated Dealer role
    const EDESIGNATED_DEALER: u64 = 6;
    /// The signer didn't have the required Validator role
    const EVALIDATOR: u64 = 7;
    /// The signer didn't have the required Validator Operator role
    const EVALIDATOR_OPERATOR: u64 = 8;
    /// The signer didn't have the required Child VASP role
    const ECHILD_VASP: u64 = 9;

    ///////////////////////////////////////////////////////////////////////////
    // Role ID constants
    ///////////////////////////////////////////////////////////////////////////

    const DIEM_ROOT_ROLE_ID: u64 = 0;
    const TREASURY_COMPLIANCE_ROLE_ID: u64 = 1;
    const DESIGNATED_DEALER_ROLE_ID: u64 = 2;
    const VALIDATOR_ROLE_ID: u64 = 3;
    const VALIDATOR_OPERATOR_ROLE_ID: u64 = 4;
    const PARENT_VASP_ROLE_ID: u64 = 5;
    const CHILD_VASP_ROLE_ID: u64 = 6;

    /// The roleId contains the role id for the account. This is only moved
    /// to an account as a top-level resource, and is otherwise immovable.
    struct RoleId has key {
        role_id: u64,
    }

    // =============
    // Role Granting

    /// Publishes diem root role. Granted only in genesis.
    public fun grant_diem_root_role(
        dr_account: &signer,
    ) {
        DiemTimestamp::assert_genesis();
        // Checks actual Diem root because Diem root role is not set
        // until next line of code.
        CoreAddresses::assert_diem_root(dr_account);
        // Grant the role to the diem root account
        grant_role(dr_account, DIEM_ROOT_ROLE_ID);
    }
    spec grant_diem_root_role {
        include DiemTimestamp::AbortsIfNotGenesis;
        include CoreAddresses::AbortsIfNotDiemRoot{account: dr_account};
        include GrantRole{addr: Signer::address_of(dr_account), role_id: DIEM_ROOT_ROLE_ID};
    }

    /// Publishes treasury compliance role. Granted only in genesis.
    public fun grant_treasury_compliance_role(
        treasury_compliance_account: &signer,
        dr_account: &signer,
    ) acquires RoleId {
        DiemTimestamp::assert_genesis();
        CoreAddresses::assert_treasury_compliance(treasury_compliance_account);
        assert_diem_root(dr_account);
        // Grant the TC role to the treasury_compliance_account
        grant_role(treasury_compliance_account, TREASURY_COMPLIANCE_ROLE_ID);
    }
    spec grant_treasury_compliance_role {
        include DiemTimestamp::AbortsIfNotGenesis;
        include CoreAddresses::AbortsIfNotTreasuryCompliance{account: treasury_compliance_account};
        include AbortsIfNotDiemRoot{account: dr_account};
        include GrantRole{addr: Signer::address_of(treasury_compliance_account), role_id: TREASURY_COMPLIANCE_ROLE_ID};
    }

    /// Publishes a DesignatedDealer `RoleId` under `new_account`.
    /// The `creating_account` must be treasury compliance.
    public fun new_designated_dealer_role(
        creating_account: &signer,
        new_account: &signer,
    ) acquires RoleId {
        assert_treasury_compliance(creating_account);
        grant_role(new_account, DESIGNATED_DEALER_ROLE_ID);
    }
    spec new_designated_dealer_role {
        include AbortsIfNotTreasuryCompliance{account: creating_account};
        include GrantRole{addr: Signer::address_of(new_account), role_id: DESIGNATED_DEALER_ROLE_ID};
    }

    /// Publish a Validator `RoleId` under `new_account`.
    /// The `creating_account` must be diem root.
    public fun new_validator_role(
        creating_account: &signer,
        new_account: &signer
    ) acquires RoleId {
        assert_diem_root(creating_account);
        grant_role(new_account, VALIDATOR_ROLE_ID);
    }
    spec new_validator_role {
        include AbortsIfNotDiemRoot{account: creating_account};
        include GrantRole{addr: Signer::address_of(new_account), role_id: VALIDATOR_ROLE_ID};
    }

    /// Publish a ValidatorOperator `RoleId` under `new_account`.
    /// The `creating_account` must be DiemRoot
    public fun new_validator_operator_role(
        creating_account: &signer,
        new_account: &signer,
    ) acquires RoleId {
        assert_diem_root(creating_account);
        grant_role(new_account, VALIDATOR_OPERATOR_ROLE_ID);
    }
    spec new_validator_operator_role {
        include AbortsIfNotDiemRoot{account: creating_account};
        include GrantRole{addr: Signer::address_of(new_account), role_id: VALIDATOR_OPERATOR_ROLE_ID};
    }

    /// Publish a ParentVASP `RoleId` under `new_account`.
    /// The `creating_account` must be TreasuryCompliance
    public fun new_parent_vasp_role(
        creating_account: &signer,
        new_account: &signer,
    ) acquires RoleId {
        assert_treasury_compliance(creating_account);
        grant_role(new_account, PARENT_VASP_ROLE_ID);
    }
    spec new_parent_vasp_role {
        include AbortsIfNotTreasuryCompliance{account: creating_account};
        include GrantRole{addr: Signer::address_of(new_account), role_id: PARENT_VASP_ROLE_ID};
    }

    /// Publish a ChildVASP `RoleId` under `new_account`.
    /// The `creating_account` must be a ParentVASP
    public fun new_child_vasp_role(
        creating_account: &signer,
        new_account: &signer,
    ) acquires RoleId {
        assert_parent_vasp_role(creating_account);
        grant_role(new_account, CHILD_VASP_ROLE_ID);
    }
    spec new_child_vasp_role {
        include AbortsIfNotParentVasp{account: creating_account};
        include GrantRole{addr: Signer::address_of(new_account), role_id: CHILD_VASP_ROLE_ID};
    }

    /// Helper function to grant a role.
    fun grant_role(account: &signer, role_id: u64) {
        assert(!exists<RoleId>(Signer::address_of(account)), Errors::already_published(EROLE_ID));
        move_to(account, RoleId { role_id });
    }
    spec grant_role {
        pragma opaque;
        include GrantRole{addr: Signer::address_of(account)};
        let addr = Signer::spec_address_of(account);
        // Requires to satisfy global invariants.
        requires role_id == DIEM_ROOT_ROLE_ID ==> addr == @DiemRoot;
        requires role_id == TREASURY_COMPLIANCE_ROLE_ID ==> addr == @TreasuryCompliance;
    }
    spec schema GrantRole {
        addr: address;
        role_id: num;
        aborts_if exists<RoleId>(addr) with Errors::ALREADY_PUBLISHED;
        ensures exists<RoleId>(addr);
        ensures global<RoleId>(addr).role_id == role_id;
        modifies global<RoleId>(addr);
    }

    // =============
    // Role Checking

    fun has_role(account: &signer, role_id: u64): bool acquires RoleId {
       let addr = Signer::address_of(account);
       exists<RoleId>(addr)
           && borrow_global<RoleId>(addr).role_id == role_id
    }

    public fun has_diem_root_role(account: &signer): bool acquires RoleId {
        has_role(account, DIEM_ROOT_ROLE_ID)
    }

    public fun has_treasury_compliance_role(account: &signer): bool acquires RoleId {
        has_role(account, TREASURY_COMPLIANCE_ROLE_ID)
    }

    public fun has_designated_dealer_role(account: &signer): bool acquires RoleId {
        has_role(account, DESIGNATED_DEALER_ROLE_ID)
    }

    public fun has_validator_role(account: &signer): bool acquires RoleId {
        has_role(account, VALIDATOR_ROLE_ID)
    }

    public fun has_validator_operator_role(account: &signer): bool acquires RoleId {
        has_role(account, VALIDATOR_OPERATOR_ROLE_ID)
    }

    public fun has_parent_VASP_role(account: &signer): bool acquires RoleId {
        has_role(account, PARENT_VASP_ROLE_ID)
    }

    public fun has_child_VASP_role(account: &signer): bool acquires RoleId {
        has_role(account, CHILD_VASP_ROLE_ID)
    }

    public fun get_role_id(a: address): u64 acquires RoleId {
        assert(exists<RoleId>(a), Errors::not_published(EROLE_ID));
        borrow_global<RoleId>(a).role_id
    }

    /// Return true if `addr` is allowed to receive and send `Diem<T>` for any T
    public fun can_hold_balance(account: &signer): bool acquires RoleId {
        // VASP accounts and designated_dealers can hold balances.
        // Administrative accounts (`Validator`, `ValidatorOperator`, `TreasuryCompliance`, and
        // `DiemRoot`) cannot.
        has_parent_VASP_role(account) ||
        has_child_VASP_role(account) ||
        has_designated_dealer_role(account)
    }

    // ===============
    // Role Assertions

    /// Assert that the account is diem root.
    public fun assert_diem_root(account: &signer) acquires RoleId {
        CoreAddresses::assert_diem_root(account);
        let addr = Signer::address_of(account);
        assert(exists<RoleId>(addr), Errors::not_published(EROLE_ID));
        assert(borrow_global<RoleId>(addr).role_id == DIEM_ROOT_ROLE_ID, Errors::requires_role(EDIEM_ROOT));
    }
    spec assert_diem_root {
        pragma opaque;
        include CoreAddresses::AbortsIfNotDiemRoot;
        include AbortsIfNotDiemRoot;
    }

    /// Assert that the account is treasury compliance.
    public fun assert_treasury_compliance(account: &signer) acquires RoleId {
        CoreAddresses::assert_treasury_compliance(account);
        let addr = Signer::address_of(account);
        assert(exists<RoleId>(addr), Errors::not_published(EROLE_ID));
        assert(
            borrow_global<RoleId>(addr).role_id == TREASURY_COMPLIANCE_ROLE_ID,
            Errors::requires_role(ETREASURY_COMPLIANCE)
        )
    }
    spec assert_treasury_compliance {
        pragma opaque;
        include AbortsIfNotTreasuryCompliance;
    }

    /// Assert that the account has the parent vasp role.
    public fun assert_parent_vasp_role(account: &signer) acquires RoleId {
        let addr = Signer::address_of(account);
        assert(exists<RoleId>(addr), Errors::not_published(EROLE_ID));
        assert(
            borrow_global<RoleId>(addr).role_id == PARENT_VASP_ROLE_ID,
            Errors::requires_role(EPARENT_VASP)
        )
    }
    spec assert_parent_vasp_role {
        pragma opaque;
        include AbortsIfNotParentVasp;
    }

    /// Assert that the account has the child vasp role.
    public fun assert_child_vasp_role(account: &signer) acquires RoleId {
        let addr = Signer::address_of(account);
        assert(exists<RoleId>(addr), Errors::not_published(EROLE_ID));
        assert(
            borrow_global<RoleId>(addr).role_id == CHILD_VASP_ROLE_ID,
            Errors::requires_role(ECHILD_VASP)
        )
    }
    spec assert_child_vasp_role {
        pragma opaque;
        include AbortsIfNotChildVasp{account: Signer::address_of(account)};
    }


    /// Assert that the account has the designated dealer role.
    public fun assert_designated_dealer(account: &signer) acquires RoleId {
        let addr = Signer::address_of(account);
        assert(exists<RoleId>(addr), Errors::not_published(EROLE_ID));
        assert(
            borrow_global<RoleId>(addr).role_id == DESIGNATED_DEALER_ROLE_ID,
            Errors::requires_role(EDESIGNATED_DEALER)
        )
    }
    spec assert_designated_dealer {
        pragma opaque;
        include AbortsIfNotDesignatedDealer;
    }

    /// Assert that the account has the validator role.
    public fun assert_validator(validator_account: &signer) acquires RoleId {
        let validator_addr = Signer::address_of(validator_account);
        assert(exists<RoleId>(validator_addr), Errors::not_published(EROLE_ID));
        assert(
            borrow_global<RoleId>(validator_addr).role_id == VALIDATOR_ROLE_ID,
            Errors::requires_role(EVALIDATOR)
        )
    }
    spec assert_validator {
        pragma opaque;
        include AbortsIfNotValidator{validator_addr: Signer::address_of(validator_account)};
    }

    /// Assert that the account has the validator operator role.
    public fun assert_validator_operator(validator_operator_account: &signer) acquires RoleId {
        let validator_operator_addr = Signer::address_of(validator_operator_account);
        assert(exists<RoleId>(validator_operator_addr), Errors::not_published(EROLE_ID));
        assert(
            borrow_global<RoleId>(validator_operator_addr).role_id == VALIDATOR_OPERATOR_ROLE_ID,
            Errors::requires_role(EVALIDATOR_OPERATOR)
        )
    }
    spec assert_validator_operator {
        pragma opaque;
        include AbortsIfNotValidatorOperator{validator_operator_addr: Signer::spec_address_of(validator_operator_account)};
    }

    /// Assert that the account has either the parent vasp or designated dealer role.
    public fun assert_parent_vasp_or_designated_dealer(account: &signer) acquires RoleId {
        let addr = Signer::address_of(account);
        assert(exists<RoleId>(addr), Errors::not_published(EROLE_ID));
        let role_id = borrow_global<RoleId>(addr).role_id;
        assert(
            role_id == PARENT_VASP_ROLE_ID || role_id == DESIGNATED_DEALER_ROLE_ID,
            Errors::requires_role(EPARENT_VASP_OR_DESIGNATED_DEALER)
        );
    }
    spec assert_parent_vasp_or_designated_dealer {
        pragma opaque;
        include AbortsIfNotParentVaspOrDesignatedDealer;
    }

    public fun assert_parent_vasp_or_child_vasp(account: &signer) acquires RoleId {
        let addr = Signer::address_of(account);
        assert(exists<RoleId>(addr), Errors::not_published(EROLE_ID));
        let role_id = borrow_global<RoleId>(addr).role_id;
        assert(
            role_id == PARENT_VASP_ROLE_ID || role_id == CHILD_VASP_ROLE_ID,
            Errors::requires_role(EPARENT_VASP_OR_CHILD_VASP)
        );
    }
    spec assert_parent_vasp_or_child_vasp {
        pragma opaque;
        include AbortsIfNotParentVaspOrChildVasp;
    }


    //**************** Module Specification ****************
    spec module {} // switch to module documentation context

    /// # Persistence of Roles

    /// Once an account at an address is granted a role it will remain an account role for all time.
    spec module {
        invariant update
            forall addr: address where old(exists<RoleId>(addr)):
                exists<RoleId>(addr) && old(global<RoleId>(addr).role_id) == global<RoleId>(addr).role_id;
    }

    /// # Access Control

    /// In this section, the conditions from the [requirements for access control][ACCESS_CONTROL] are systematically
    /// applied to the functions in this module. While some of those conditions have already been
    /// included in individual function specifications, listing them here again gives additional
    /// assurance that that all requirements are covered.

    spec module {
        /// The DiemRoot role is only granted in genesis [[A1]][ROLE]. A new `RoleId` with `DIEM_ROOT_ROLE_ID` is only
        /// published through `grant_diem_root_role` which aborts if it is not invoked in genesis.
        apply ThisRoleIsNotNewlyPublished{this: DIEM_ROOT_ROLE_ID} to * except grant_diem_root_role, grant_role;
        apply DiemTimestamp::AbortsIfNotGenesis to grant_diem_root_role;

        /// TreasuryCompliance role is only granted in genesis [[A2]][ROLE]. A new `RoleId` with `TREASURY_COMPLIANCE_ROLE_ID` is only
        /// published through `grant_treasury_compliance_role` which aborts if it is not invoked in genesis.
        apply ThisRoleIsNotNewlyPublished{this: TREASURY_COMPLIANCE_ROLE_ID} to *
            except grant_treasury_compliance_role, grant_role;
        apply DiemTimestamp::AbortsIfNotGenesis to grant_treasury_compliance_role;

        /// Validator roles are only granted by DiemRoot [[A3]][ROLE]. A new `RoleId` with `VALIDATOR_ROLE_ID` is only
        /// published through `new_validator_role` which aborts if `creating_account` does not have the DiemRoot role.
        apply ThisRoleIsNotNewlyPublished{this: VALIDATOR_ROLE_ID} to * except new_validator_role, grant_role;
        apply AbortsIfNotDiemRoot{account: creating_account} to new_validator_role;

        /// ValidatorOperator roles are only granted by DiemRoot [[A4]][ROLE]. A new `RoleId` with `VALIDATOR_OPERATOR_ROLE_ID` is only
        /// published through `new_validator_operator_role` which aborts if `creating_account` does not have the DiemRoot role.
        apply ThisRoleIsNotNewlyPublished{this: VALIDATOR_OPERATOR_ROLE_ID} to *
            except new_validator_operator_role, grant_role;
        apply AbortsIfNotDiemRoot{account: creating_account} to new_validator_operator_role;

        /// DesignatedDealer roles are only granted by TreasuryCompliance [[A5]][ROLE]. A new `RoleId` with `DESIGNATED_DEALER_ROLE_ID()`
        /// is only published through `new_designated_dealer_role` which aborts if `creating_account` does not have the
        /// TreasuryCompliance role.
        apply ThisRoleIsNotNewlyPublished{this: DESIGNATED_DEALER_ROLE_ID} to *
            except new_designated_dealer_role, grant_role;
        apply AbortsIfNotTreasuryCompliance{account: creating_account} to new_designated_dealer_role;

        /// ParentVASP roles are only granted by TreasuryCompliance [[A6]][ROLE]. A new `RoleId` with `PARENT_VASP_ROLE_ID()` is only
        /// published through `new_parent_vasp_role` which aborts if `creating_account` does not have the TreasuryCompliance role.
        apply ThisRoleIsNotNewlyPublished{this: PARENT_VASP_ROLE_ID} to * except new_parent_vasp_role, grant_role;
        apply AbortsIfNotTreasuryCompliance{account: creating_account} to new_parent_vasp_role;

        /// ChildVASP roles are only granted by ParentVASP [[A7]][ROLE]. A new `RoleId` with `CHILD_VASP_ROLE_ID` is only
        /// published through `new_child_vasp_role` which aborts if `creating_account` does not have the ParentVASP role.
        apply ThisRoleIsNotNewlyPublished{this: CHILD_VASP_ROLE_ID} to * except new_child_vasp_role, grant_role;
        apply AbortsIfNotParentVasp{account: creating_account} to new_child_vasp_role;

        /// The DiemRoot role is globally unique [[B1]][ROLE], and is published at DIEM_ROOT_ADDRESS [[C1]][ROLE].
        /// In other words, a `RoleId` with `DIEM_ROOT_ROLE_ID` uniquely exists at `DIEM_ROOT_ADDRESS`.
        invariant [global, isolated] forall addr: address where spec_has_diem_root_role_addr(addr):
          addr == @DiemRoot;
        invariant [global, isolated]
            DiemTimestamp::is_operating() ==> spec_has_diem_root_role_addr(@DiemRoot);

        /// The TreasuryCompliance role is globally unique [[B2]][ROLE], and is published at TREASURY_COMPLIANCE_ADDRESS [[C2]][ROLE].
        /// In other words, a `RoleId` with `TREASURY_COMPLIANCE_ROLE_ID` uniquely exists at `TREASURY_COMPLIANCE_ADDRESS`.
        invariant [global, isolated] forall addr: address where spec_has_treasury_compliance_role_addr(addr):
          addr == @TreasuryCompliance;
        invariant [global, isolated]
            DiemTimestamp::is_operating() ==>
                spec_has_treasury_compliance_role_addr(@TreasuryCompliance);

        // TODO: These specs really just repeat what's in spec_can_hold_balance_addr. It's nice to
        // be able to link to DIP-2, but can we do that with less verbose specs?
        /// DiemRoot cannot have balances [[D1]][ROLE].
        invariant [global, isolated] forall addr: address where spec_has_diem_root_role_addr(addr):
            !spec_can_hold_balance_addr(addr);

        /// TreasuryCompliance cannot have balances [[D2]][ROLE].
        invariant [global, isolated] forall addr: address where spec_has_treasury_compliance_role_addr(addr):
            !spec_can_hold_balance_addr(addr);

        /// Validator cannot have balances [[D3]][ROLE].
        invariant [global, isolated] forall addr: address where spec_has_validator_role_addr(addr):
            !spec_can_hold_balance_addr(addr);

        /// ValidatorOperator cannot have balances [[D4]][ROLE].
        invariant [global, isolated] forall addr: address where spec_has_validator_operator_role_addr(addr):
            !spec_can_hold_balance_addr(addr);

        /// DesignatedDealer have balances [[D5]][ROLE].
        invariant [global, isolated] forall addr: address where spec_has_designated_dealer_role_addr(addr):
            spec_can_hold_balance_addr(addr);

        /// ParentVASP have balances [[D6]][ROLE].
        invariant [global, isolated] forall addr: address where spec_has_parent_VASP_role_addr(addr):
            spec_can_hold_balance_addr(addr);

        /// ChildVASP have balances [[D7]][ROLE].
        invariant [global, isolated] forall addr: address where spec_has_child_VASP_role_addr(addr):
            spec_can_hold_balance_addr(addr);
    }

    /// # Helper Functions and Schemas

    spec module {
        fun spec_get_role_id(addr: address): u64 {
            global<RoleId>(addr).role_id
        }

        fun spec_has_role_id_addr(addr: address, role_id: u64): bool {
            exists<RoleId>(addr) && global<RoleId>(addr).role_id == role_id
        }

        fun spec_has_diem_root_role_addr(addr: address): bool {
            spec_has_role_id_addr(addr, DIEM_ROOT_ROLE_ID)
        }

        fun spec_has_treasury_compliance_role_addr(addr: address): bool {
            spec_has_role_id_addr(addr, TREASURY_COMPLIANCE_ROLE_ID)
        }

        fun spec_has_designated_dealer_role_addr(addr: address): bool {
            spec_has_role_id_addr(addr, DESIGNATED_DEALER_ROLE_ID)
        }

        fun spec_has_validator_role_addr(addr: address): bool {
            spec_has_role_id_addr(addr, VALIDATOR_ROLE_ID)
        }

        fun spec_has_validator_operator_role_addr(addr: address): bool {
            spec_has_role_id_addr(addr, VALIDATOR_OPERATOR_ROLE_ID)
        }

        fun spec_has_parent_VASP_role_addr(addr: address): bool {
            spec_has_role_id_addr(addr, PARENT_VASP_ROLE_ID)
        }

        fun spec_has_child_VASP_role_addr(addr: address): bool {
            spec_has_role_id_addr(addr, CHILD_VASP_ROLE_ID)
        }

        fun spec_can_hold_balance_addr(addr: address): bool {
            spec_has_parent_VASP_role_addr(addr) ||
                spec_has_child_VASP_role_addr(addr) ||
                spec_has_designated_dealer_role_addr(addr)
        }
    }

    spec schema ThisRoleIsNotNewlyPublished {
        this: u64;
        ensures forall addr: address where exists<RoleId>(addr) && global<RoleId>(addr).role_id == this:
            old(exists<RoleId>(addr)) && old(global<RoleId>(addr).role_id) == this;
    }

    spec schema AbortsIfNotDiemRoot {
        account: signer;
        include CoreAddresses::AbortsIfNotDiemRoot;
        let addr = Signer::spec_address_of(account);
        aborts_if !exists<RoleId>(addr) with Errors::NOT_PUBLISHED;
        aborts_if global<RoleId>(addr).role_id != DIEM_ROOT_ROLE_ID with Errors::REQUIRES_ROLE;
    }

    spec schema AbortsIfNotTreasuryCompliance {
        account: signer;
        include CoreAddresses::AbortsIfNotTreasuryCompliance;
        let addr = Signer::spec_address_of(account);
        aborts_if !exists<RoleId>(addr) with Errors::NOT_PUBLISHED;
        aborts_if global<RoleId>(addr).role_id != TREASURY_COMPLIANCE_ROLE_ID with Errors::REQUIRES_ROLE;
    }

    spec schema AbortsIfNotParentVasp {
        account: signer;
        let addr = Signer::spec_address_of(account);
        aborts_if !exists<RoleId>(addr) with Errors::NOT_PUBLISHED;
        aborts_if global<RoleId>(addr).role_id != PARENT_VASP_ROLE_ID with Errors::REQUIRES_ROLE;
    }

    spec schema AbortsIfNotChildVasp {
        account: address;
        aborts_if !exists<RoleId>(account) with Errors::NOT_PUBLISHED;
        aborts_if global<RoleId>(account).role_id != CHILD_VASP_ROLE_ID with Errors::REQUIRES_ROLE;
    }

    spec schema AbortsIfNotDesignatedDealer {
        account: signer;
        let addr = Signer::spec_address_of(account);
        aborts_if !exists<RoleId>(addr) with Errors::NOT_PUBLISHED;
        aborts_if global<RoleId>(addr).role_id != DESIGNATED_DEALER_ROLE_ID with Errors::REQUIRES_ROLE;
    }

    spec schema AbortsIfNotParentVaspOrDesignatedDealer {
        account: signer;
        let addr = Signer::spec_address_of(account);
        aborts_if !exists<RoleId>(addr) with Errors::NOT_PUBLISHED;
        let role_id = global<RoleId>(addr).role_id;
        aborts_if role_id != PARENT_VASP_ROLE_ID && role_id != DESIGNATED_DEALER_ROLE_ID
            with Errors::REQUIRES_ROLE;
    }

    spec schema AbortsIfNotParentVaspOrChildVasp {
        account: signer;
        let addr = Signer::spec_address_of(account);
        aborts_if !exists<RoleId>(addr) with Errors::NOT_PUBLISHED;
        let role_id = global<RoleId>(addr).role_id;
        aborts_if role_id != PARENT_VASP_ROLE_ID && role_id != CHILD_VASP_ROLE_ID
            with Errors::REQUIRES_ROLE;
    }

    spec schema AbortsIfNotValidator {
        validator_addr: address;
        aborts_if !exists<RoleId>(validator_addr) with Errors::NOT_PUBLISHED;
        aborts_if global<RoleId>(validator_addr).role_id != VALIDATOR_ROLE_ID with Errors::REQUIRES_ROLE;
    }

    spec schema AbortsIfNotValidatorOperator {
        validator_operator_addr: address;
        aborts_if !exists<RoleId>(validator_operator_addr) with Errors::NOT_PUBLISHED;
        aborts_if global<RoleId>(validator_operator_addr).role_id != VALIDATOR_OPERATOR_ROLE_ID
            with Errors::REQUIRES_ROLE;
    }
}
