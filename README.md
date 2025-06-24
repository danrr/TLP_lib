# TLP_lib

This repository contains the implementation of multiple flavours of time-lock puzzles:
- [Delegated Generic Multiple Instance Time-Lock Puzzle](https://arxiv.org/abs/2308.01280)
- [Generic Multiple Instance Time-Lock Puzzle](https://arxiv.org/abs/2308.01280)
- [Multiple Instance Time-Lock Puzzle by Abadi & Kiayias](https://doi.org/10.1007/978-3-662-64331-0_28)
- [Original Time-Lock Puzzle by Rivest, Shamir & Wagner](https://dl.acm.org/doi/10.5555/888615)

## Installation

Create virtual env:
```sh
 python3 -m venv .venv         
```

Activate virtual env:
```sh
source .venv/bin/activate
```

```sh
pip install ".[all]"
```

## Development
Install editable package:
```sh
pip install -e ".[all]" --group all
```

## Testing
Includes tests for all implemented puzzles. Run with

```sh
pytest
```
