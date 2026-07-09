# Build and Run

These instructions can be used to build and run the project.

## Setup

### 1. Initialize dev environment

```
make environment
```

### 2. Install the `electionguard` module in edit mode

```
make install
```

!!! warning "Note: gmpy2 Windows Installation"

    **Recommended: Use Windows Subsystem for Linux (WSL)**

    _WSL supports the generic workflow for installtion._

    1. Install [WSL](https://docs.microsoft.com/en-us/windows/wsl/install). 
    2. Return to **1. Initialize dev environment**

    **Alternative: Install pre-compiled binary**

    _uv supports `--find-links`, so a local pre-compiled binary can be supplied without editing `pyproject.toml`._

    1. Determine if 64-bit:
        _The 32 vs 64 bit is based on your installed python version NOT your system._
        This code snippet will read true for 64 bit.
    ```py
    python -c 'from sys import maxsize; print(maxsize > 2**32)'
    ```
    2. Download [pre-compiled binary](https://www.lfd.uci.edu/~gohlke/pythonlibs/#gmpy) into a `packages` folder in the project.
    3. Run `uv sync` with the local package folder.
    ```sh
    uv sync --all-groups --find-links ./packages
    ```

### 3. Validate import of module _(Optional)_

```
make validate
```

## Running

### Option 1: Code Coverage

```
make coverage
```

### Option 2: Run tests in VS Code

Install recommended test explorer extensions and run unit tests through tool.

**⚠️ Note:** For Windows, be sure to select the [virtual environment Python interpreter](https://docs.microsoft.com/en-us/visualstudio/python/installing-python-interpreters).

### Option 3: Run test command

```
make test
```
