bo---
id: v2-docs-guide
title: V2 Docs Guide
sidebar_label: V2 Docs Guide
---

<br />

## Excerpt

<Excerpt image="img/white-paper-excerpt.svg">
  The world truly needs a reliable digital currency and infrastructure that together can deliver on the promise of “the internet of money.” Securing your financial assets on your mobile device should be simple and intuitive. Moving money around globally should be as easy and cost-effective as — and even more safe and secure than — sending a text message or sharing a photo, no matter where you live, what you do, or how much you earn.
   &nbsp;<a href='#'>— Diem White Paper</a>
</Excerpt>

## Multi Step Code Snippet

<MultiStepSnippet
  defaultValue="js"
  values={[
    { value: 'js', label: (
      <ColorCard
        color="purpleDark"
        icon="img/transaction.svg"
        iconDark="img/transaction-dark.svg"
        overlay="Send a test transaction to orem ipsum dolor sit amet, ctetur adipiscing elit, sed do"
        title="Send a test transaction"
        type="snippetTab"
      />
    )},
    { value: 'py', label: (
      <ColorCard
        color="purpleLight"
        icon="img/bobby-pin.svg"
        iconDark="img/bobby-pin-dark.svg"
        overlay="Second overlay (no content specified in comps"
        title="Write a move program"
        type="snippetTab"
      />
    )},
    { value: 'java', label: (
      <ColorCard
        color="aqua"
        icon="img/overlapping-circle-and-square.svg"
        iconDark="img/overlapping-circle-and-square-dark.svg"
        overlay="Third overlay (no content specified in comps"
        title="Try out a wallet"
        type="snippetTab"
      />
    )},
  ]
}>
<MultiStepTabItem value="js">

```jsx
import React, { useState } from 'react';

function Example() {
  const [count, setCount] = useState(0);

  return (
    <div>
      <p>You clicked {count} times</p>
      <button className="button primary" onClick={() => setCount(count + 1)}>
        Click me
      </button>
    </div>
  );
}

function Example() {
  const [count, setCount] = useState(0);

  return (
    <div>
      <p>You clicked {count} times</p>
      <button onClick={() => setCount(count + 1)}>
        Click me
      </button>
    </div>
  );
}

function Example() {
  const [count, setCount] = useState(0);

  return (
    <div>
      <p>You clicked {count} times</p>
      <button onClick={() => setCount(count + 1)}>
        Click me
      </button>
    </div>
  );
}
```

</MultiStepTabItem>
<MultiStepTabItem value="py">

```py
def hello_world():
  print('Hello, world!')
```

</MultiStepTabItem>
<MultiStepTabItem value="java">

```java
class HelloWorld {
  public static void main(String args[]) {
    System.out.println("Hello, World");
  }
}
```

</MultiStepTabItem>
</MultiStepSnippet>


## Cards

### Color Card

<CardsWrapper>
  <ColorCard
    color="purpleDark"
    icon="img/transaction.svg"
    iconDark="img/transaction-dark.svg"
    to="#"
    title="Send a test transaction"
  />
</CardsWrapper>

### Overlay Card

<CardsWrapper>
  <OverlayCard
    description="I want to understand nodes"
    icon="img/wallet-app.svg"
    iconDark="img/wallet-app-dark.svg"
    title="Nodes"
    to="#"
  />
</CardsWrapper>

### Simple Card

<CardsWrapper>
  <SimpleTextCard
    icon="img/github.svg"
    iconDark="img/github-dark.svg"
    title="Read the core specifications"
    to="#"
  />
</CardsWrapper>

### Tag Card

<CardsWrapper>
  <TagCard
    icon="img/github.svg"
    iconDark="img/github-dark.svg"
    tags={["Web", "Mobile", "Merchant"]}
    title="Reference Wallet"
    to="https://github.com/diem"
  />
</CardsWrapper>

## Reference Section Component

<CardsWrapper>
  <CoreReference />
  <MerchantReference />
  <WalletReference />
  <MoveReference />
  <NodeReference />
</CardsWrapper>

<WaveBackground />

## Normal Code Snippet (and the start of WaveBackground)


```jsx
import React, { useState } from "react";

function Example() {
  const [count, setCount] = useState(0);

  return (
    <div>
      <p>You clicked {count} times</p>
      <button onClick={() => setCount(count + 1)}>
        Click me
      </button>
    </div>
  );
}
```

## Excerpt (with WaveBackground)

<Excerpt image="img/white-paper-excerpt.svg">
  The world truly needs a reliable digital currency and infrastructure that together can deliver on the promise of “the internet of money.” Securing your financial assets on your mobile device should be simple and intuitive. Moving money around globally should be as easy and cost-effective as — and even more safe and secure than — sending a text message or sharing a photo, no matter where you live, what you do, or how much you earn.
   &nbsp;<a href='#'>— Diem White Paper</a>
</Excerpt>

## Multi Step Code Snippet (with WaveBackground)

<MultiStepSnippet
  defaultValue="js"
  values={[
    { value: 'js', label: (
      <ColorCard
        color="purpleDark"
        icon="img/transaction.svg"
        iconDark="img/transaction-dark.svg"
        overlay="Send a test transaction to orem ipsum dolor sit amet, ctetur adipiscing elit, sed do"
        title="Send a test transaction"
        type="snippetTab"
      />
    )},
    { value: 'py', label: (
      <ColorCard
        color="purpleLight"
        icon="img/bobby-pin.svg"
        iconDark="img/bobby-pin-dark.svg"
        overlay="Second overlay (no content specified in comps"
        title="Write a move program"
        type="snippetTab"
      />
    )},
    { value: 'java', label: (
      <ColorCard
        color="aqua"
        icon="img/overlapping-circle-and-square.svg"
        iconDark="img/overlapping-circle-and-square-dark.svg"
        overlay="Third overlay (no content specified in comps"
        title="Try out a wallet"
        type="snippetTab"
      />
    )},
  ]
}>
<MultiStepTabItem value="js">

```jsx
import React, { useState } from 'react';

function Example() {
  const [count, setCount] = useState(0);

  return (
    <div>
      <p>You clicked {count} times</p>
      <button className="button primary" onClick={() => setCount(count + 1)}>
        Click me
      </button>
    </div>
  );
}

function Example() {
  const [count, setCount] = useState(0);

  return (
    <div>
      <p>You clicked {count} times</p>
      <button onClick={() => setCount(count + 1)}>
        Click me
      </button>
    </div>
  );
}

function Example() {
  const [count, setCount] = useState(0);

  return (
    <div>
      <p>You clicked {count} times</p>
      <button onClick={() => setCount(count + 1)}>
        Click me
      </button>
    </div>
  );
}
```

</MultiStepTabItem>
<MultiStepTabItem value="py">

```py
def hello_world():
  print('Hello, world!')
```

</MultiStepTabItem>
<MultiStepTabItem value="java">

```java
class HelloWorld {
  public static void main(String args[]) {
    System.out.println("Hello, World");
  }
}
```

</MultiStepTabItem>
</MultiStepSnippet>

## Multi Step Code Snippet with 5 Tabs (with WaveBackground)
<MultiStepSnippet
  defaultValue="js"
  values={[
    { value: 'js', label: (
      <ColorCard
        color="purpleDark"
        icon="img/transaction.svg"
        iconDark="img/transaction-dark.svg"
        overlay="Some random overlay"
        title="Send a test transaction"
        type="snippetTab"
      />
    )},
    { value: 'py', label: (
      <ColorCard
        color="purpleLight"
        icon="img/bobby-pin.svg"
        iconDark="img/bobby-pin-dark.svg"
        title="Write a move program"
        type="snippetTab"
      />
    )},
    { value: 'java', label: (
      <ColorCard
        color="aqua"
        icon="img/overlapping-circle-and-square.svg"
        iconDark="img/overlapping-circle-and-square-dark.svg"
        title="Try out a wallet"
        type="snippetTab"
      />
    )},
    { value: 'fourth', label: (
      <ColorCard
        color="purpleLight"
        icon="img/overlapping-circle-and-square.svg"
        iconDark="img/overlapping-circle-and-square-dark.svg"
        overlay="Another random overlay"
        title="Test of the fourth tab"
        type="snippetTab"
      />
    )},
    { value: 'fifth', label: (
      <ColorCard
        color="purpleDark"
        icon="img/overlapping-circle-and-square.svg"
        iconDark="img/overlapping-circle-and-square-dark.svg"
        overlay="Another random overlay"
        title="Test of the fifth tab"
        type="snippetTab"
      />
    )},
  ]
}>
<MultiStepTabItem value="js">

```jsx
import React, { useState } from "react";

function Example() {
  const [count, setCount] = useState(0);

  return (
    <div>
      <p>You clicked {count} times</p>
      <button onClick={() => setCount(count + 1)}>
        Click me
      </button>
    </div>
  );
}

function Example() {
  const [count, setCount] = useState(0);

  return (
    <div>
      <p>You clicked {count} times</p>
      <button onClick={() => setCount(count + 1)}>
        Click me
      </button>
    </div>
  );
}

function Example() {
  const [count, setCount] = useState(0);

  return (
    <div>
      <p>You clicked {count} times</p>
      <button onClick={() => setCount(count + 1)}>
        Click me
      </button>
    </div>
  );
}
```

</MultiStepTabItem>
<MultiStepTabItem value="py">

```py
def hello_world():
  print('Hello, world!')
```

</MultiStepTabItem>
<MultiStepTabItem value="java">

```java
class HelloWorld {
  public static void main(String args[]) {
    System.out.println("Hello, World");
  }
}
```

</MultiStepTabItem>
<MultiStepTabItem value="fourth">

```java
class HeyYalllllll {
  public static void main(String args[]) {
    System.out.println("Hello!!!!, World");
  }
}
```

</MultiStepTabItem>
<MultiStepTabItem value="fifth">

```jsx
function test() {
  console.log(123);
}
```

</MultiStepTabItem>

</MultiStepSnippet>
