...

## Usage

You probably want to run the plain versions to calculate the correct inputs. You can then use them to prove using the ZK implementations.

### Typescript

Clone this repository and navigate to the `typescript` directory. Install dependencies:

```bash
npm i # or `pnpm i`, `bun i`, etc
```

The library will be built in `typescript/dist`, you can import it through npm links, [gitpkg](https://gitpkg.vercel.app/), copying it into your `node_modules` (YOLO!)... whatever floats your boat.

You can then use it in your project:

```ts
import { computeAllInputs } from 'plume-sig';

const messageBytes = new Uint8Array([ 104, 101, 108, 108, 111,  32, 110, 111, 105, 114 ]) // bytes for "hello noir"
const privateKey = "signers_private_key;
const { nullifier } = await computeAllInputs(messageBytes, privateKey);
```

### Noir

Once you have your inputs, you can import the `noir` package into your project. Add the dependency to your `Nargo.toml` file:

```toml
plume = { tag = "main", git = "https://github.com/plume-sig/zk-nullifier-sig", directory = "circuits/noir/plume" }
```

You can prove your PLUME nullifier is valid like so:

```nr
let plume = Plume::new(message, scalar_c, scalar_s, pubkey_bg, nullifier);
plume.plume_v2();
```

The Noir PLUME implementation is fairly generic, however you need to provide your own `hash_to_curve` implementation. Currently we're only testing for `secp256k1` and `bn254`.

So for `secp256k1` you probably want to cast your values to `Secp256k1Fq` BigNum, `Secp256k1` Curve, `Secp256k1Scalar`, etc. For example:

```rust
// use noir_bigcurve::curves::secp256k1::{Secp256k1, Secp256k1Fq, Secp256k1Scalar};

let c_bn = Secp256k1Fq::from_be_bytes(c);
let scalar_c: Secp256k1Scalar = ScalarField::from_bignum(c_bn);
let s_bn = Secp256k1Fq::from_be_bytes(s);
let scalar_s: Secp256k1Scalar = ScalarField::from_bignum(s_bn);
let pubkey_bg = Secp256k1 {
   x: Secp256k1Fq::from_be_bytes(pub_key_x),
   y: Secp256k1Fq::from_be_bytes(pub_key_y),
   is_infinity: false,
};
let nullifier = Secp256k1 {
   x: Secp256k1Fq::from_be_bytes(nullifier_x),
   y: Secp256k1Fq::from_be_bytes(nullifier_y),
   is_infinity: false,
};

```

### Noir

Noir provides its own testing environment. Install [Nargo](https://noir-lang.org/docs/getting_started/noir_installation):

```bash
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash # installs noirup, the nargo installer
noirup # installs nargo
```

Then navigate to `circuits/noir`, and run tests:

```bash
nargo test
```

Tests should finish in around 30-60 seconds.