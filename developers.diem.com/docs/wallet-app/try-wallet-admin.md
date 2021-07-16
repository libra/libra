---
id: try-wallet-admin
title: 'Reference Wallet Admin Dashboard'
sidebar_label: The Admin Dashboard
---

## Overview

This tutorial will walk you through logging in to and using the Diem Reference Wallet admin dashboard. 

The admin dashboard allows admin users to perform several administrative tasks such as:

*   Reviewing registered users
*   Blocking users
*   Adding new admin users
*   Settling liquidity provider debt

> **Note**:
> * You can use the admin credentials in the tutorial below only in your local web version of the Diem Reference Wallet.
> * The admin dashboard is not accessible in the mobile app. 
> * The admin user is not available for the public demo. 

 


## Logging in


To access the admin dashboard:
1. On the log in page, click on 'Forgot Password'. 
2. You will be prompted to enter a user email to reset your password. Use `admin@lrw`. This admin user will always exist in the Diem Reference Wallet. 
3. The page that loads first says that the reset password email has been sent to your account. Then you will automatically be redirected to the next page, where you can enter and confirm a new password. 
4. Enter and confirm your new admin password and click 'Submit'. 
5. Log in using the username `admin@lrw` and the new password you created. 

You will be redirected to the main page of the admin dashboard, which is different from the main page of a regular user. 



## Main page

The main page of the admin dashboard shows the total number of registered users and the total wallet balances for each Diem Coin currency. The admin dashboard also contains the following pages that can help you manage several administrative tasks: 

*   User management
*   Administrators management
*   Liquidity management

![Figure 1.0 Reference Wallet admin dashboard](/img/docs/admin-dash.png)


## User and admin management pages

Both these pages offer a list of users. Clicking “Block” button will force the user to be logged out immediately and prevent them from entering the system again.

On the administrators management page, the “Add administrator” button allows adding a new admin user to the system.


## Liquidity management page

This page simulates management of the wallet debt for its liquidity provider. The wallet continuously sells and buys funds from the liquidity provider. While the test Diem Coins are immediately transferred, the corresponding fiat amount is accumulated and settled manually. 

In real-world scenarios, the settlement usually involves some kind of wire transfer. In the Diem Reference Wallet, clicking “Settle” marks the debt as settled immediately (for demo purposes only).

###### tags: `wallet`
