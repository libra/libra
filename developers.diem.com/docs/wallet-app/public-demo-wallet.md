---
id: public-demo-wallet
title: 'Try the Public Demo Wallet'
sidebar_label: Wallet Demo
---



## Overview

The Public Demo Wallet has been made available to allow the public to try out a wallet running on the testnet. It is meant to run as a public, online demo service. While Public Demo Wallet users may transfer test Diem Coins on the testnet, transfer of fiat currency, actually minted Diem Coins, or other funds are simulated. The Public Demo Wallet demonstrates the following use cases:

* Sending Diem Coins to another Diem wallet address.
* Receiving Diem Coins from another Diem wallet address.
* Exchanging fiat money for Diem Coins and vice versa.
* Converting between the different Diem Coins.
* Viewing transaction history.
* Basic risk management and AML compliance flows.

The main purpose is to demonstrate common use cases for Diem Coins custodial wallets. To illustrate key concepts, we’ve simplified the implementation and avoided some of the complexities of real world, production-grade financial software.

>
>Note: The wallet uses simulated user information.
>



### User flows

The image below details the different user flows for the Public Demo Wallet.

![Figure 1.0 Different user flows for the Public Demo Wallet](/img/docs/userflows-demo-wallet.svg)



### Use the Demo Wallet

<iframe src="https://demo-wallet.diem.com/login/" />

Click <a href="/reference-wallet" target="_blank">here</a> for a full page version of this demo

## Create your account and login

Since this is a demo, login and authentication is simulated using auto generated fake user data.

### Register and sign up

New users who want to use the Public Demo Wallet go through a simulated registration process. Users should enter a dummy username and password at signup and choose from a dummy identity during the sign up process.

The registration process simulates the following steps:

* Protects the user’s personal information.
* Assessment of the risks involved in maintaining a business relationship with the user.
* Compliance with KYC guidelines and AML regulations.

During registration, the user of the Public Demo Wallet is presented with the screen shots and process flows that simulate a user asked to provide the information that would be required for proper identity verification and account security. The simulated registration process collects this information in multiple steps:

1. Login credentials, including a strong and unique password.
2. Personal details, including name, date of birth, and phone number.
3. Country of residence.
4. Address.
5.  Photograph of an officially recognized identification document (e.g., a passport or driver’s license, as defined by the local jurisdiction).
6.  The base currency used for presentation of the conversion rates.

All login details for the Public Demo Wallet will be fake, auto-generated credentials for dummy identities. The account verification begins once the user completes the registration demo. The user won’t be able to access the Public Demo Wallet until they have gone through the simulated account verification process.

>
>Note: Account verification demos the expected behavior of a hypothetical wallet. For the Public Demo Wallet, the verification succeeds automatically and the “pending” state is presented briefly to the user for demo purposes only. In addition, the identification document is always accepted and is not analysed or stored by the backend. Real-world user verification and risk management are beyond the scope of the reference wallet and contain many opportunities for further development.
>

Read more about the user verification [in the Risk section](/docs/wallet-app/develop-reference-wallet/#risk-module).

### Sign in
The Public Demo Wallet is only accessible to authenticated users. When a user accesses the wallet website, the login page is the first page presented to the user. This is where the user is authenticated using the auto generated username and password.

Upon login, if a user is presented with a “Verification Pending” page, it means that the authentication has been successful but the user verification process is still underway.

If the user is not yet registered, they can proceed to register by activating the “Sign up” link on the page.


### Sign out
A user can sign out of the wallet on the [Settings](#modify-settings) page.

### Reset password
It is possible to reset the user password by entering a username on the password reset page. The page is accessible by following the “Forgot Password” link on the login page. The password reset flow is simulated where the user has to enter the fake username and is redirected to a page where they have to enter their new dummy password.

>
>Note: For the reference wallet, entering an existing username redirects the user immediately to the password change page, without sending the reset message.
>



## View home page

The home page is where most user actions are performed, and an overview of the wallet balances can be seen. The balances are displayed separately for each Diem Coins currency and as an approximation of the total amount.

User actions available on the home page include:

* View full transaction history for a Diem Coins currency; this can be activated by clicking an item in the balances list.
* Send Diem Coins.
* Receive Diem Coins.
* Add Diem Coins to the wallet; activated by clicking “Transfer” and then “Add.”
* Withdraw Diem Coins from the wallet; activated by clicking “Transfer” and then “Withdraw.”
* Convert between Diem Coins currencies

![Figure 2.0 Demo Wallet home page](/img/docs/wallet-home.svg)





## Modify settings

On the Settings page, a user can sign out from the wallet, edit general preferences, and add payment methods.

The modifiable preferences are:

* Local currency—affects the base currency used in the currency exchange operations throughout the wallet.
* User interface language.

The supported payment methods are:
* Credit cards
* Bank accounts

In addition, the page shows the simulated username of the fictional active user. It is not possible to change the user’s username.

![Figure 2.1 Public Demo Wallet settings page](/img/docs/modify-settings.svg)

>
>Note: The payment methods are for demonstration purposes only. The supplied information is not validated, and no real transactions are made using the configured credit cards and bank accounts. Users of the Public Demo Wallet will not be permitted to enter real credit card or bank account information.
>



To change the wallet UI language, enter the Settings page and choose the desired language from the languages dropdown menu
![Figure 2.3 choose language](/img/docs/language-settings.svg)

## Execute transactions

### View transactions list

Choosing a specific Diem Coins currency on the home page shows all the wallet transactions for that currency in descending order. Transactions may be internal (i.e., off-chain), within the wallet’s network (e.g., Diem Coins transfer between customers of the same wallet service), or external (i.e., on-chain) on the Diem Blockchain (e.g., Diem transfer to some external Diem address).

![Figure 3.0 View list of transactions](/img/docs/execute-transactions.png)

Each transaction consists of:

* Direction (sent or received)
* Address
* Amount of Diem Coins
* Current fiat value in default fiat currency, as configured in the wallet settings
* Transaction execution date

### Check transaction details

Clicking a transaction in the transactions list will open a window with transaction details.

![Figure 3.1 View transaction details](/img/docs/check-transaction.png)



Each transaction consists of:

* Direction (sent or received)
* Amount of Diem Coins
* Current fiat value in default fiat currency, as configured in the wallet settings
* Transaction execution date and time
* Address
* Diem transaction ID – Diem Blockchain transaction’s ledger version number with link to an external Diem Blockchain explorer, if applicable. If not applicable, as in the cases of internal transactions, the field will be marked as unavailable.



### Deposit and withdraw Diem Coins

Users can simulate the deposit and withdraw Diem Coins to and from the Public Demo Web Wallet.

When a user deposits a Diem Coins currency amount, the Public Demo Web Wallet simulates a purchase of Diem Coins using the user's credit card or bank account wire transfer.

>
>Note: For safety and security, the reference wallet does not support the entry of actual credit card or bank account details.
>

To perform a deposit, follow these steps:

1. Make sure you have a payment method defined. Payment methods can be defined [on the Settings page](#modify-settings).
2. On the home page click “Transfer.”
3. Choose “Add.”
4. The user will be presented with a deposit dialog. You should specify:
   a. The funding method, which is one of the configured credit cards or bank accounts.
   b. The Diem Coins currency to purchase.
   c. The amount to deposit. The deposit amount can be specified either in Diem Coins or in the fiat currency of choice; the wallet will calculate the correct price or the resulting Diem amount accordingly and reflect that in the dialog.
5. Click “Review.” The view will change to a confirmation dialog summarizing the purchase details, including the exchange rate.
6. Click “Confirm” to execute the purchase. Clicking on “Back” allows modification of the purchase details. Clicking on “X” in the top right corner cancels the operation.
7. Upon execution, the added funds will be reflected in the balances summary on the home page and in the transactions list.

The Diem withdrawal process is performed by clicking “Transfer” and then “Withdraw.” The process behaves very similarly to the deposit process. Upon withdrawal execution, the specified amount is deducted from the user balances.


### Convert between Diem currencies

>
>Note: In a production application, this function may be subject to regulatory and licensing obligations for the service providers involved. See Prospective VASPs to learn more.
>

To convert from one Diem currency to another:

1. On the home page click 'Transfer'.
2. Choose 'Convert.''
3. The conversion dialog will be presented. You should specify:
    a. The source Diem Coins currency.
    b. The target Diem Coins currency.
    c. The amount, either in terms of the source or the target currency; the converted amount is calculated and reflected automatically to the user.
4. Click “Review.” The view will change to a confirmation dialog summarizing the conversion details, including the exchange rate.
5. Click “Confirm” to execute the conversion. Clicking on “Back” allows modification of the purchase details. Clicking on “X” in the top right corner cancels the operation.
6. Upon execution, the changes will be reflected in the balances summary on the home page and in the transactions list.


### Send Diem Coins

To send Diem Coins to another address:

1. On the home page click “Send.”
2. The send dialog will be presented. You should specify:
    a. The specific Diem Coins currency
    b. The Diem Blockchain destination address
    c. The amount, either in terms of the Diem Coins currency or in terms of a fiat currency of choice; the counterpart is calculated and reflected automatically to the user.
3. Click “Review.” The view will change to a confirmation dialog summarizing the transaction details, including the exchange rate.
4. Click “Confirm” to execute the transaction. Clicking on “Back” allows modification of the purchase details. Clicking on “X” in the top right corner cancels the operation.
5. Upon execution, the changes will be reflected in the balances summary on the home page and in the transactions list.


### Receive Diem Coins

Other wallets can simulate sending funds without any action on the receiving party’s side, assuming they know the recipient’s target address. To see the address of a wallet, click “Request” on the home page. A wallet has a different address for each Diem Coins currency. To get the correct address, the user should verify that the right currency is selected. The actual address is presented at the bottom of the dialog as clear text. It can be copied into the clipboard by clicking the available button, or scanned using the QR code.


###### tags: `wallet`
