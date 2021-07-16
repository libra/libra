---
id: develop-drm
title: Reference Merchant Development
sidebar_label: Set Up and Develop
---



## Setup

To set up your environment or deploy the Diem Reference Merchant, refer to the latest information [here](https://github.com/diem/reference-merchant).

The Diem Reference Merchant is available as a web application. All web UI resources can also be found [here](https://github.com/diem/reference-merchant/tree/master/merchant/frontend).

#### GitHub repository

https://github.com/diem/reference-merchant



## Merchant front-end module

The merchant front-end module demonstrates the merchant’s online store UI. It communicates with the merchant back-end and the VASP module to carry out its commands.

### Implementation

The Merchant front-end is a React app written in TypeScript.

### Extend functionality

Use a robust e-commerce solution for a reliable online store implementation.

## Merchant back-end module

The Merchant back-end is a service performing all the product management and payment operations for the merchant front-end.

### Implementation
The merchant back-end module is implemented in Python, manifesting a RESTful API using Flask.

### Extend functionality
The merchant back-end would usually be a part of a complete e-commerce solution, together with the front-end.

## VASP module
The VASP module is an autonomous service that performs all the Diem-related operations for the merchant back-end and front-end modules.

### Implementation
The VASP module is implemented in Python, manifesting a RESTful API using Flask; it uses Postgresql for data persistence.

### Extend functionality
The proposed VASP reference implementation is centered on serving an online retailer. However, VASPs could supply a wide range of services, including wallets, liquidity, trading, and more.

## Use cases

### Direct payment under US$1,000
In this use case, the user pays for a product using Diem Coins from his wallet directly to the Regulated VASP. Since no additional verification is required for amounts under US$1,000, the user wallet posts the transaction directly to the Diem Blockchain. The merchant settles the payment later using the payout procedure.


.![Figure 1.0 Use case: Direct payments under US$1000](/img/docs/direct-payment-usecase.svg)

### Payment payout
Payout is a procedure between a merchant and its payment VASP. Payout causes the funds collected from a client by the VASP for some previous purchase, to be transferred to the merchant in the form of a fiat deposit to the merchant’s bank account. The VASP employs a liquidity provider (as an external service) to convert Diem funds to a fiat currency.

Paid out payments are not refundable.


![Figure 1.1 Use case: Payment payouts](/img/docs/payment-payouts.svg)

Notice that the Diem Reference Merchant does not demonstrate the final fiat transfer and focuses only on the Diem operations.

### Payment refund
Refund is an operation triggered by the merchant that returns the payment to its origin. The operation creates a new blockchain transaction in the opposite direction from the original payment transaction.

## Localization
The UI is fully translatable using standard React i18n library [react-i18next](https://react.i18next.com/). All texts are mapped in JSON files located at front-end/src/locales/LANGUAGE. To generate new translations, a script is available to auto-generate new translations using a third-party translation service or to export all existing text into a CSV file for manual translation. Located at scripts/generate_i18n.py are usage example for translating from English to Spanish; ./scripts/generate_i18n.py -s en -d es -a will use EN JSON files located at front-end/src/locales/en and generate new JSON files at front-end/src/locales/es. Instructions for using the newly generated files will be shown upon completing these steps:
1. Add `import ES from "./es";` to front-end/src/locales/index.ts
2. Add `es: ES;` to the default Resource object in there

To extract translations into a CSV file for manual translations, you can use the export flag:
`./scripts/generate_i18n.py -s en -d es -e ./english_texts.csv`
To import manually translated CSV you can use the import flag:
`./scripts/generate_i18n.py -s en -d es -i ./english_texts.csv`


###### tags: `merchant`
