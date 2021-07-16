---
id: try-demo-merchant
title: Try the Demo Merchant Service
sidebar_label: Merchant Demo
wider_content: true
---

## Overview

The Public Demo Merchant Store has been made available to allow the public to try out a merchant store running on the testnet. It is meant to run as a public, online demo service.

#### Assumptions
The Public Demo Merchant service makes several assumptions for simplicity:
* None of the products are real and no actual purchases are made.
* The checkout process focuses on payment and bypasses common steps such as shipping details.
* Users can “buy” products in the merchant online store without any registration or authentication.
* The merchant’s payment management UI is accessible without any authentication.

The main purpose of this demo is to demonstrate common use cases when working with Diem Coin currencies.

<Spacer />

<iframe src="https://demo-merchant.diem.com/"></iframe>



## User flows
### Direct payment under US$1,000

Direct payments under US$1,000 do not require any special AML procedures and are processed immediately.
1. Open the merchant store.
2. Choose a product under US$1,000 and click “Buy now.”
3. The checkout dialog window will open.
4. Select the desired Diem Coin currency.
5. The calculated price in the selected Diem Coin currency will be displayed.
6. Scan the QR code or copy the deep-link into a Diem wallet of your choice.
7. Complete the payment in the wallet.

The checkout dialog will confirm payment success.


Notice the payment ID link at the bottom of the dialog. It can be used to access the payment management page.


###### tags: `merchant`
