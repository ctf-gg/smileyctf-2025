<!-- readme format inspiration from https://github.com/project-sekai-ctf/sekaictf-2024 -->

# smileyctf-2025

Challenge source code and solve scripts for [smileyCTF 2025](https://ctftime.org/event/2591).

## directory structure

```txt
category/
├── challenge/
    ├── dist/
    │   └── files that should be distributed to player (handout)
    ├── chall/
    │   └── challenge files, including deployment-related files and actual flag.txt
    ├── src/
    │   └── any files for building. source code.
    ├── solve/
    │   └── scripts, etc. that solve the challenge
    └── README.md
        └── challenge description and overview
```

## challenges

### misc

| Name                                      | Author             | Solves |
|-------------------------------------------|--------------------|--------|
| [Sanity Check](misc/sanity-check)         | .;,;.              | 1,023  |
| [sky](misc/sky)                           | smashmaster        | 100    |
| [cowsay](misc/cowsay)                     | matthew            | 87     |
| [TI-1983](misc/ti-1983)                   | snow               | 62     |
| [mulitsig-wallet](misc/multisig-wallet)   | BrokenAppendix     | 52     |
| [Project Holoswap](misc/project-holoswap) | sahuang            | 28     |
| [vs-math-ai](misc/vs-math-ai)             | jayden             | 15     |
| [offset](misc/offset)                     | helloperson / snow | 14     |
| [TI-1984](misc/ti-1984)                   | snow               | 3      |

### rev

| Name                                     | Author  | Solves |
|------------------------------------------|---------|--------|
| [Success](rev/success)                   | flocto  | 674    |
| [fORtran](rev/fORtran)                   | neil    | 306    |
| [Easy Come Easy Go](rev/easycome-easygo) | flocto  | 176    |
| [DNA](rev/dna)                           | flocto  | 55     |
| [liqUID glASS](rev/liqUID%20glASS)       | sahuang | 33     |
| [Fruit Ninja](rev/fruitninja)            | flocto  | 8      |
| [100r1cs](rev/100r1cs)                   | snow    | 0      |
| [tables](rev/tables)                     | lunbun  | 0      |

### pwn

| Name                               | Author    | Solves |
|------------------------------------|-----------|--------|
| [debuggable-1](pwn/debuggable-1)   | unvariant | 122    |
| [debuggable-2](pwn/debuggable-2)   | unvariant | 75     |
| [babyrop](pwn/babyrop)             | Eth007    | 70     |
| [blargh](pwn/blargh)               | nootkroot | 38     |
| [limit](pwn/limit)                 | cope      | 34     |
| [debuggable-3](pwn/debuggable-3)   | unvariant | 7      |
| [teemo-tuesday](pwn/teemo-tuesday) | unvariant | 3      |
| [accelerator](pwn/accelerator)     | unvariant | 2      |

### crypto

| Name                                                            | Author           | Solves |
|-----------------------------------------------------------------|------------------|--------|
| [saas](crypto/saas)                                             | snow             | 279    |
| [never enough](crypto/never-enough)                             | snow             | 72     |
| [LCGs are SBGs](crypto/lcgsaresbgs)                             | SuperBeetleGamer | 18     |
| [a special place in reality](crypto/a-special-place-in-reality) | helloperson      | 10     |
| [sums](crypto/sums)                                             | snow             | 6      |
| [spontaneous](crypto/spontaneous)                               | snow             | 4      |
| [flcg](crypto/flcg)                                             | helloperson      | 1      |

### web

| Name                                                   | Author      | Solves |
|--------------------------------------------------------|-------------|--------|
| [Sculpture Revenge](web/sculpture-revenge)             | smashmaster | 144    |
| [Extension Mania](web/extension-mania)                 | smashmaster | 128    |
| [dry-ice-n-co](web/dry-ice-n-co)                       | voxal       | 61     |
| [Extension Mania revenge](web/extension-mania-revenge) | smashmaster | 55     |
| [Teemo's Secret](web/teemos-secret)                    | Chara       | 11     |
| [Teemo's Secret v2](web/teemos-secret-v2)              | Chara       | ?      |
| [Leaf](web/leaf)                                       | Chara       | 3      |

### forensics

| Name                                 | Author | Solves |
|--------------------------------------|--------|--------|
| [rorecovery2](forensics/rorecovery2) | neil   | 53     |
| [rorecovery1](forensics/rorecovery1) | neil   | 18     |
| [rorecovery3](forensics/rorecovery3) | neil   | 10     |

### guessctf

| Name     | Author      | Solves |
|----------|-------------|--------|
| guessctf | helloperson | 0      |


## License

All source code in this repository are licensed under the [GNU Affero General Public License 3.0](LICENSE):

<blockquote>
Challenge source code and solve scripts for smileyCTF 2025

Copyright (C) 2025 smiley foundation

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
</blockquote>