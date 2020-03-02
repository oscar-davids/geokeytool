# Authorship

Copyright (C) Philipp Andreas Angele - All Rights Reserved

Written by Philipp Andreas Angele <philipp_angele@gmx.de>, Feb 2020

RSA: 66A8 6285 2AE0 C1D5 0733  C9C7 1A6C 6EC6 75F1 0E56 

# Title

Geokeys for Bitcoin and Ether and other killer apps like pgp, ssh

# Introduction

Today it is hard for anyone to recover a private key from memory. Brainkey implementations usually require the user to memorize a set of words. Most implementations want the user to remember a set of 12-24 words.
While it is possible to memorize those seed phrases it is also very likely to forget them and highly unlikely that a user can quickly transfer them to another user without revealing the secret to unwanted listeners.
Other key recovery methods have dependencies on either a trusted party or a decentralized application. Those leave the user at risk of losing access to their keys by either the trusted party removing your access or a bug in a dApp can lock your access as well. 

In this paper, we propose a private key recovery system that allows people to remember/recover it without any accessories or aids. The system needs just a location and a password to recover a key.
We prove that neither the key nor the encryption are weakened by this system. 
The simplicity of the implementation allows us to get rid of: 

* a middleman, 

* a smart contract

* a centralized recovery system, 

* an online connection

As we will see further below, this empowers users to: 

* create and memorize a key with very low chances of forgetting it 

* quickly transfer a key verbally to another person

* recover their key at a low cost

all without revealing the entropy in clear text.

# Abstract

This paper proposes a key recovery method that uses a known and a partially known secret that forces the recovery to use a brute force mechanism to get to the full secret of the partial secret and that validates the results with the existence of the key on a blockchain, ledger, database... .

A ECDSA or other cryptographic key pair might be built using one or many known secrets and one or many partially known secrets.
Once this key has interacted with a blockchain, ledger... it is possible to recover it by creating all possible keys with the known and the partial known secret(s) by guessing the missing part(s) of the partial secret(s).
To identify which was the original key to recover all created keys need to be looked up on a blockchain or ledger as only the one which has interacted with it will be traceable there.

## Working principle

A user generating a private key picks a precise location from a map and a password. 

A key generator uses the password and the location's geo coordinates as salt and digests everything with a high computational cost (in our PoC BCrypt) to create a ECDSA key-pair. The precision of the geo location needs to be known down to a meter level but the key generator will add a random and unknown decimal degree up to 1 millimeter depending on the targeted security of the key.

As we will see, we generate entropy by having every square centimeter on Earth in combination with an infinite number of possible passwords.

To recover the key the user will have to brute force all coordinates around the location on a scale of square meters with the known password. The location is quite vague since the user never knew which centimeter he chose from the map when he generated the key but only roughly the position. He will have to try through all possible square centimeter around the location he set. This will take a bit of time to recover the key but the chance for the user who knows the location and the password is high. For state of the art technology this will be on the scale of 1 computational day or 1$. For an attacker, the chance to guess both location and password is negligible. Even for a known password and an approximate guess of the location (i.e. to know which city) does not significantly speed up the brute force process.

Since every generated key is valid, both the attacker and the user have to check all created keys to have a balance on the blockchain in order to identify the one they wanted to recover. 

## Conjecture

Emotions are the best incorporeal storage in meatspace.

The emotional connection to locations make them an easy thing to remember. One can transfer the  key easily to someone without revealing the information in clear text and thus without reducing the entropy. 
An example: "The place where we kissed the first time and the nickname of our child when it wasn't born yet is the map to my treasure." 
This sentence would be enough for your partner to recover the key and it would be a low security risk to even say this in a room with many people listening. Yet the entropy of the information has been sufficiently transported. Your partner would have a big advantage at least to brute force to the example quicker as someone who might guess part of the secret like the name of the unborn child, even if he additionally can guess part of the location like the region or city.
Humans store informations by attaching them to emotions. This is how our brain links information and how it prioritizes the lifetime (time to live = TTL) of information. The stronger the emotion the better we remember.

The probability of guessing both location and password is low:
For a mm range we are estimating the earth surface with 5,101e^+20 millimeter x n possibilities, while n is defined by the amount of tries the attacker is planning. If you consider only urban areas, take 0.1% of earth's surface.

A scale in Millimeters is resulting in very strong encryption as there are 100 times more possibilities than with cm or  1e^6 times more than meter. Still the encryption for a single meter is good enough for smaller amounts. The definition hereof is done by the decimal-degree of the geo coordinates in the salt. (metric is just a rounded value to make presentation easier since the coordinates are not metric.
000.00000001 = 1.1132 mm(equator) - 1.0247 mm(northpole)

If the location is known and the password isn’t, there is still a financial obstacle for the attack:
The cost of the attack is proportionally higher than the recovery cost.
In a wordlist attack of 10.000.000 words the attack would have 10.000.000 times the cost of the recovery itself. If a user has to spend 1$ or 1 day in computational efforts for recovery from a single password, the attack would cost 10.000.000$ or take 10.000.000 GPUs for one day with 10.000.000 passwords. If the balance of the key is below the attack cost or if the attack will not yield more than the computational efforts would yield with useful work like POW mining, the attacker is disincentivized to do the attack.

If the location and your password leaked, you put yourself in a bad position and your only chance is that you find the key and move the balance somewhere else, before an attacker does. 

## Hashing Function

To strengthen the keys against any type of guessing or brute forcing attach we use a double hashing with a compute intensive hashing algorithm.

In our PoC we use BCrypt but any hashing function that introduces a time/cost variable will work, for example SCrypt or Argon2.

We chose BCrypt for this implementation because of its long successful lifetime and the ability to sequence the hashing for parallelization.  

To keep the keys deterministic, which is a requirement to be able to recover them, we needed to get rid of the randomness in the hashing function in the elliptic curve and replace it with something deterministic that is hard but not impossible to guess.

- input1 = password

- input2 = coordinates in decimal degrees

Remark: The definition of which variable is contained in input 1 and 2 is arbitrary, but needs to be aligned on.

## Prepare

`step1` BCrypt hashes the `input1` with the `salt==input2` at `n` rounds. This results in `output1`

`step2` BCrypt hashes the `input2` with the `salt==output1` at `n` rounds. This results in `output2`

`step3` ECDSA with `output1` and `output2==salt`. This results into private key

Rounds in bcrypt are defined to slow a single hash digest down to about 500ms on a state of the art GPU.

Recovery GPU Time Cost (Jan 2020)

2x bcrypt 2e19 rounds on Nvidia 1080ti

estimated cost is 1$ per day since this is the max amount you could make with mining.

On mm^2 the cost of recovery from 9m^2 is about 104 GPU days or 104$

On cm^2 the cost of recovery from 9m^2 is about 24 GPU hours or 1$

On dm^2 the cost of recovery from 9m^2 is about 14 GPU minutes or 0.01$

On m^2 the cost of recovery from 9m^2 is about 9 GPU seconds or 0.0001$

We can estimate using Shannon's Source Coding Theorem the maximum entropy in bits that such a system can provide

`\lceil \log _2\left(x^10\left(36\times \:y^{z+1}-1\right)\left(2\times \:y^{z+1}-1\right)\right)\rceil  == E`

 After plugging in the values 95(charset), 10(number of chars), and (7+1)(decimaldegree of location) for x(charset), y(number of chars) and z(decimaldegree of location) respectively, we obtain an ideal value (E) of 132-bits. This value provides us with a key-space which is more than the recommended 128. 
 
`\lceil \log _2\left(95^10\left(36\times \:10^{8+1}-1\right)\left(2\times \:10^{8+1}-1\right)\right)\rceil == E`

132 bits entropy can be reached with the following password length and location quantifier:

- a password of 9 chars, a charset of 95 and a location quantifier of mm (8+1)

- a password of 10 chars, a charset of 95 and a location quantifier of cm (7+1)

- a password of 11 chars, a charset of 95 and a location quantifier of dm (6+1)

- a password of 12 chars, a charset of 95 and a location quantifier of m (5+1)

Lowering chars on the password will result in loss of appropriate entropy.

Lowering space on quantifier will result in weakness against wordlist attacks.

## Key Validation:

Calculate balance from public keys.

Each created public key is used to calculate if it has a balance on the blockchain. Only the one that has a balance needs to be stored the rest can be deleted.

## Difficulty adjustments

Every 4 years it is needed to reset the default rounds of security to match state of the art hashing.

This also means to stay backwards compatible. You will have to do both the old default rounds and any new default rounds separately. We start in 2020 with recommended bcrypt cost of 19 (524288 rounds)

## Recommended storage time:

Since computers become faster over time, the time you store wealth behind such a key needs to be limited. Even so Moore's law makes it predictable when another difficulty adjustment is necessary, the recommendation is to create new keys at least every 4 years (assuming a  max security decrease of times 16) and transfer funds to the new keys.

Specialist hardware and parallel computation for recovery:

It is possible to build specialized hardware that can perform more hashes per watt/cost than GPUs can. Last FPGAs updates on the topic promise a four times better efficiency and since BCrypt is not memory intensive, it can be further optimized. 

Compared to CPU performance per Watt GPUs are already yielding about 35 times the efficiency and FPGAs 144 times.

If the specialized hardware one day outperforms user equipment at a few magnitudes, as it happened with bitcoin Asic mining, key recovery can be computed in parallel with a cloud computing provider that rents this specialized equipment. This will allow to further harden the difficulty of a brute force with additional rounds in BCrypt but will keep the requirements on the initial key generator to a minimum to match user devices that wont contain specialized hardware. (in other words it is ok if the single key generation on a phone takes a minute if the recovery time can also happen in a minute) The draw back on it is that one day if this hardware exist, key recovery will become increasingly difficult with own hardware and will need the scaled recovery architecture to match performance of an attacker one day.  

Awareness of infinite lifetime of keys:

Making the keys deterministic also means encryption on anything you send will not stay secure forever.One day even so the elliptic curve cryptography might still not be broken, GPUs, FPGAs or ASICs might be fast enough to brute force to your old key and decrypt your old data. SO DON'T ENCRYPT PRIVATE STUFF WITH IT THAT SHOULD NEVER BE SEEN AGAIN!

## Alibaba and the forty thieves:

Old stories already hint the way to this encryption scheme.

In Alibaba knowing the location and the password: "Open Simsim" was enough to get access to the thieves magic cave, but forgetting only parts of the secret had the severe consequence to be stuck in the hideout. The missing memory on the secret made the hero unsuccessfully brute force through all kinds of possibilities since he forgot to remember the exact password but had still a memory on parts of its entropy which was that it was "Open (a specific grain)".

Similar applies with the GeoKeys. Someone trying to recover it from parts of the entropy will have still much higher chances than someone guessing all of it.

The location and password was leaked cause the thieves had bad OpSec and revealed the location by opening the secret gate without realizing they were spied at. Same applies to the GeoKeys. 

If you reveal where you search and what you search for someone might sniff that information and try to brute force faster than you. Your advantage is that other than the thieves you do not have to be physically present to do your search. Map data is more accurate and secure than real time GPS tracking and creation and recovery can happen completely offline.

## First use case:

Of course this technique might not be secure enough to store millions of $$$ forever behind one key. For smaller amounts and limited time it works out well though. The reason I came up with this is inspired by stories I heard from refugees like my grandparents, losing every tiny bit they had when they were forced to flee from their country. 

Back then there was no bitcoin and they tried to hide what they had on their bodies. This tool increases the chances of wealth being well hidden from aggressors and recoverable for those in the greatest need.

## Other types of implementations:

Geo locations are just one way to get to a vague secret.
Other implementations are possible as long as they have enough quantification possibilities.
In geokeys we use the space abstraction meter to millimeter. This can be replaced with something similar that is easy to remember for a human and comes with the ability to quantify it down to smaller and smaller chunks. One could use a time-date instead of an vague location for example, and to recover brute force down to milliseconds of the exact time of the date the key was created with.

# Credits

Thanks to my family who are very supportive with my ideas.

Thanks to Jochen Mader from Germany for creating the first python poc script.

Thanks to Oscar Davids from China for creating the openCL based recovery tool.

Thanks to Hashcat for providing state of the art open source brute force technology.

Thanks to Marc Cymontkowski and Fredrik Hocke from Germany for helping with the paper.

Thanks to red4sec from Spain for guidance on entropy calculations

Philipp Angele 02/2020

# Installation

1. Build Parallel Bcrypt Engine 

  - install gcc and dependency pacakges

      `sudo apt install gcc`

      `sudo apt install build-essential`

      `sudo apt-get install manpages-dev`

      `sudo apt install ocl-icd-* opencl-headers`

- Get a copy of the geokeytool repository

  `git clone https://github.com/oscar-davids/geokeytool`

- Run `make`

  `cd geokeytool`
  
  `make`
  
- check engine so file 
 
  `libclibhash.so.5.1.0`
 
2. Install Dependencies:

- Install required python packages

  `sudo pip install -r requirements.txt`
  
3. Create Keys

`python geokeys.py --create --password donotqwerty --gps +40.73150000,-73.96328000 --round 524288 --unit cm`

`--password` : Choose a easy to remember Password (try to have at least 13 chars use Capital letters numbers and special chars)

`--gps` : Collect Geo Coordinates in Decimaldegrees of location 

`--round` : the number of rounds bcrypt will hash. (524288 minimum recommendation year 2020)

`--unit` : choose the quanitfier for the location (m, dm, cm, mm will define how long a recovery search takes)


The output contains the ECDSA keys and die resulting Bitcoin wallet import format WIF:

```
{
"password":"aaaaa", 
"gps":"+40.73150430,-73.96328390", 
"bcrypt output1":"$2a$19$XES0XUK3L0HkMBGzMESxM.ZhpdqZfjfoAwkoejes7GR9Plujl5oXy", 
"bcrypt output2":"$2a$19$WhPiWUSyWhjfXRC3XRWuWeZL1bfJgh0ILOLAM9bZpy8jzWAJQmEV.", 
"private key":"005a4c3162664a676830494c4f4c414d39625a7079386a7a57414a516d45562f", 
"public key":"049be5cdf427e5a895079ca692dab3549e3345d48140d6867800b6c9047962fd8bdbf4f7440a62234ab842b30e088b695c70824cd63b2a400d5f02c29cd509be76", 
"bitcoin address":"004c22cb5dae25afa2ceb6ba8d2e2fc42bbc8ad6c106964a9f", 
"bitcoin address base58":"17wa38uT7SZEz9pWpv6JN5qhZHe8rSbDhY", 
"wif":"5HpSbFifKDMTonAH6NfLBL52fkAaq8EzGdQSioRQAq27VPMTrpF"
}
```

From here you can backup the key and use it as you wish.

For recovery:

1. Prepare step 1-2 

2. Install Bitcoin client 

  `https://bitcoin.org/en/full-node`
  
- start bitcoin with daemon mode

3. Generate local bitcoin UTXO database 

- stop bitcoin daemon because can not access bitcoin's database at once.
  
  `bitcoin-cli stop`
 
- dump UTXO set from chainstate
  
  `python updatebtcdb.py $HOME/.bitcoin/chainstate`
  
4. Recovery of keys
  
  `python geokeys.py --recover --password donotqwerty --gps +40.73150390,-73.96328405 --round 524288 --unit dm --radius 0.5`
  
`--password` :  Remember your Password

`--gps` : Collect Geo Coordinates in Decimaldegrees of location 

`--round` : Use same rounds as with creation (524288 minimum recommendation year 2020)

`--unit` : choose the maximum quanitfier for the search (m, dm, cm, mm, all)

`--radius` : in meter defines the search area relative to your geo coordinates 

`--debug` : creates debug output file containing all tries

After a successful search you will find your keys in a local text file and in your terminal.

From here you can backup the key and use it as you wish.

The OpenCL bcrypt digest makes use of GPUs and FPGAs such as in crypto mining rigs work for the scaled recovery.
