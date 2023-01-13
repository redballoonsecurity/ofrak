# Angr Backend

## Install

Like the Ghidra backend, Angr is distributed with the OFRAK docker image. 

## Usage

To use Angr, you need to discover the components at setup-time with:

```python
ofrak = OFRAK(logging.INFO)
ofrak.injector.discover(ofrak_angr)
```

!!! warning
    You can only use one of these analysis backends at a time (angr OR Binary Ninja OR Ghidra)

### Angr auto-analysis

Using Angr auto-analysis is transparent after the components are discovered, you don't 
have to do anything!

## Documentation

[Angr User Documentation](https://docs.angr.io/)

