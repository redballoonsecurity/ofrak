# Angr Backend

## Install

An OFRAK container with the angr backend can be built with:
```bash
python3 build_image.py --config ofrak-angr.yml --base --finish

## Usage

To use angr, you need to discover the components at setup-time with:

```python
ofrak = OFRAK(logging.INFO)
ofrak.injector.discover(ofrak_angr)
ofrak.injector.discover(ofrak_capstone)
```

Note that the angr backend is designed to be used in conjunction with the Capstone backend, which implements `BasicBlockUnpacker`.

!!! warning
    You can only use one of these analysis backends at a time (angr OR Binary Ninja OR Ghidra)

### Angr auto-analysis

Using angr auto-analysis is transparent after the components are discovered, you don't 
have to do anything!

## Documentation

[Angr User Documentation](https://docs.angr.io/)
