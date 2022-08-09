# OFRAK Components
Components are the modular unit of work that are the building blocks of OFRAK.

The base interface of OFRAK components is [ComponentInterface][ofrak.component.interface.ComponentInterface]. All components in OFRAK currently subclass [AbstractComponent][ofrak.component.abstract.AbstractComponent], which contains some helper functions that are shared across components.

OFRAK components are grouped together by the following abstract interfaces:

- [Identifier](./identifier.md)
- [Unpacker](./unpacker.md)
- [Analyzer](./analyzer.md)
- [Modifier](./modifier.md)
- [Packer](./packer.md)

<div align="right">
<img src="../../assets/square_04.png" width="125" height="125">
</div>
