# Writing Modifiers
To write an OFRAK [Modifier](../../user-guide/component/modifier.md), an OFRAK contributor needs to:

1. Create a class that inherits from `ofrak.component.component_modifier.Modifier` with a defined component config (`ofrak.model.component_model.CC`);
2. Implement the `targets` to indicate what resource tags the modifier targets;
3. Implement the `modify` method such that it correctly applies the modifications.

See [Modifier](../../user-guide/component/modifier.md) for an example of a fully-implemented OFRAK modifier.

<div align="right">
<img src="../../assets/square_05.png" width="125" height="125">
</div>
