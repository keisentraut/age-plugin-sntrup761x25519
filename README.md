# age-plugin-sntrup761x25519

Post quantum safe encryption for [rage](https://github.com/str4d/rage/) with a combination of ```sntrup761``` and ```x25519```.
Even if the newer ```sntrup761``` algorithm will turn out as weak, this should still be as safe as the classic ```x25519```.

I wrote this in order to learn Rust and play with ```sntrup761```.

## How to build

```
git clone https://github.com/keisentraut/age-plugin-sntrup761x25519.git
cargo build --release
```

Then, ensure that the ```age-plugin-sntrup761x25519``` binary is in your ```PATH``` environmental variable.
For instance, you could run one of the following commands:

- ```export PATH=$PATH:$(pwd)/target/release/```
- ```ln -s $(pwd)/target/release/age-plugin-sntrup761x25519 /usr/local/bin/age-plugin-sntrup761x25519```

## Disclaimers

### WARNING: UNSTABLE
The file format is considered unstable and future versions might not be able to decrypt files encrypted with older versions.
If you rely on this plugin, then you might need to re-encrypt all your data if changes are made.

### WARNING: NOT REVIEWED
This was written in my spare time mostly in order to learn Rust.

I am only a hobby cryptographer.
The code has not been reviewed and there is a chance that it has errors.
The encryption might not be as strong as you think. 

## How to run and use

### Key generation

Run the plugin executable without any arguments in order to generate an key.

```
$ age-plugin-sntrup761x25519 | tee my_sntrup761x25519_identity
# created: 2022-04-28T23:14:54+02:00
# public key: age1sntrup761x255191tzex99...lpy5ghy05a7g9qvq3ht
AGE-PLUGIN-SNTRUP761X25519-1FQ7PAA7LQQ29PX3HKX...0YH6F6777DGD5L5YPWDR
```

```
$ cat my_sntrup761x25519_identity | grep -F '# public key: ' | cut -d ' ' -f4 | tee my_sntrup761x25519_identity.pub
age1sntrup761x255191tzex99...lpy5ghy05a7g9qvq3ht
```

This plugin recipients/identities have two downsides compared to the standard age X25519 recipients:

- Recipients and keys are very large: an encoded recipient is 1930 chars long and an encoded secret key is 2906 chars!
  The main reason for this is that ```sntrup761``` algorithm has a public key size of 1158 bytes and a secret key size of 1763 bytes. 
  Some additional bytes are required for the ```x25519``` keys and checksums. 
  Finally, the Bech32 encoding creates an extra length increase of +60% plus some checksums.
- There is no way to get the public key from the private key (i.e. no ```age-keygen -y``` equivalent).
  I think it is mathematically possible to do this with ```sntrup761``` but the ```pqcrypto``` library does not have such a interface. 
  So please always store both the secret and the public key.

### En-/Decryption

So far, only the [rage](https://github.com/str4d/rage) implementation supports plugins. 
If you have installed this plugin, you can use rage as you would with other recipients.
An encryption looks like the following:

```
$ echo test | rage -R my_sntrup761x25519_identity.pub | tee test.age
age-encryption.org/v1
-> sntrup761x25519 NEQ/5NUW8ukiq6dUFoU9jPs3MTq6lSpr9x4aszyljQw= tFfRkvJF...Pegmcg==
CuhJz9d/6HAdNt1IfMYTMteU0TjIjOePVRXe5DDHdWY
-> '4P]-grease K"=0 $ur31R/ {Q3+DtK_
PjnDOJwdmA1/
--- qjrjChy1yXZgNklSzioc7BJdJiu/rOIkJCGs4boE0x0
[... binary gibberish ...]
```

```
$ cat test.age | rage -i my_sntrup761x25519_identity -d 
test
```

Please note that the encrypted file will only be post-quantum safe if there are only ```scrypt``` or ```sntrup761x25519``` recipients. 
If you mingle in ```x25519``` recipients, then your encryption will not be post-quantum safe anymore.


## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

## TODO / known issues

- refactor code, especially stanza parsing
- provide unit tests
