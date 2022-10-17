# ResourceView

## Introduction

A `ResourceView` is a Python class which represents some firmware abstraction. It is another way
of "looking at" an OFRAK resource, with an interface specific to that firmware abstraction. For
example:

```python
elf = await resource.view_as(Elf)
for section in elf.get_sections():
    print(section.name)
```
`elf` is an instance of the `Elf` `ResourceView`. It has a method `get_sections` which is
specific to ELF files. This method gets the resources of each section in the ELF, and then gets a
 view of them as an `ElfSection`. The `ElfSection` view has a field `name` which corresponds to
 an attribute of the underlying resource.

A class inheriting from `ResourceView` is also a valid tag to use on resources - It is a
`ResourceTag`. Really it is a special case, a `ViewableResourceTag`, which means that a resource
with this tag can supply a `ResourceView` of that type. In the previous example, `resource` must
have been tagged as an `Elf`.

A `ResourceView` is a dataclass,
 so it has a number of fields and an auto-generated constructor to populate them. It may also
 have some methods. A `ResourceView` can be used on its own, and like a normal Python class. For
 example you can instantiate views, and set/get their fields without interacting with an OFRAK
 resource at all.

We can look at another example:

```python
@dataclass
class Symbol(ResourceView):
  name: str
  vaddr: int

# Simple to instantiate
new_sym = Symbol("main", 0x1000100)
print(new_sym.name)  # >> "main"
print(hex(new_sym.vaddr))  # >> "0x100000"
```
The example shows how a viewable tag is declared (`Symbol`) and how it can be used independently
of any resources. We can also get a view from a resource, once the resource has that viewable tag:

```python
my_resource.add_tag(Symbol)
my_sym = await my_resource.view_as(Symbol)

print(my_sym.name)
print(hex(my_sym.vaddr))
```

The output of the last 2 print statements is not shown.
What actual values does that view have? Where do they come from? This is explained in the next
section.

## ResourceView and ResourceAttributes

In short, when the view is
 created in the `view_as` call, OFRAK attempts to analyze the resource to find those values. Like
 a normal `analyze` call, it will first check if the resource already has up-to-date attributes
 and use those; otherwise it will look for an appropriate analyzer. In this case the attributes
 do not exist, and OFRAK will look for an analyzer which outputs `Symbol.attributes_type`. `
 .attributes_type` is simply a way to access the class of `ResourceAttributes` associated with
 `Symbol`. This `ResourceAttributes` class is automatically generated.

We don't need to rely on an analyzer - we can also add the attributes manually:

```python
my_resource.add_tag(Symbol)
my_resource.add_attributes(Symbol.attributes_type("foo", 0x1000200))
my_sym = await my_resource.view_as(Symbol)

print(my_sym.name)  # >> "foo"
print(hex(my_sym.vaddr))  # >> "0x1000200"
```

ResourceViews provide a way to access the underlying resource (if it exists). `.resource` returns a
`Resource` and is how you should access the resource when you need it. If the view does
not have an underlying resource, a `ValueError` is raised:

```python
new_sym = Symbol("main", 0x1000100)
new_sym.resource  # ValueError("Cannot access ResourceView's resource because it has not been set!")
```

## Relationship Between View and Resource

Adding methods to get other resources/views related to the current resource is a common pattern.
Because this depends on the view having a resource, it will fail for views which are not created
from a resource. One rule of thumb to avoid accidentally calling a method which requires an
underlying resource is that methods which interact with the resource tree must be async;
**therefore synchronous methods are almost always safe to call, while asynchronous methods probably
 require an underlying resource.**


Not only can you create a view from a resource, but you can go the other way around:

```python
new_sym = Symbol("main", 0x1000100)
new_sym_r = await parent_resource.create_child_from_view(new_sym, data_range=Range(0x120, 0x140))
new_sym2 = await new_sym_r.view_as(Symbol)
```

Notice that when we create the child, we need to pass in a data range. The view does not hold any
 information about the data or data mapping, so that must be supplied when the resource is
 created. Once `new_sym_r` is created, we can again request a view from it. We'll find that it
 has all the same attributes as the original `new_sym`.
 
Views are read-only: **Modifying the fields of a view will not modify the 
attributes of the underlying resource, nor 
will modifying the attributes of the underlying resources automatically update the fields of an 
existing view.** Instead, the underlying resource should be explicitly modified (ideally by a 
`Modifier` component) and then a new view should be created by calling `resource.view_as(...)` 
again.

```python
my_sym1 = await my_resource.view_as(Symbol)
my_sym1.name = "get_pwned"

my_sym2 = await my_resource.view_as(Symbol)
assert my_sym1.name == my_sym2.name  # Fails because only the field of my_sym1 is changed!
await my_sym1.resource.run(ExampleSymbolModifier, ExampleSymbolModifierConfig("modified name"))
assert my_sym1.name == "modified name"  # Fails because the view is not modified, only the resource
assert my_sym2.name == "modified name"  # Fails because the view is not modified, only the resource

my_sym3 = await my_resource.view_as(Symbol)
assert my_sym3.name == "modified name"  # Passes because fresh view includes resource modification

```


## When To Use

Now that you know how to use views, when **should** you use them? Get a view of a resource
when you either need to access functionality that a view provides through one of its methods, or
when you are going to be reading several attributes from a resource.

<div align="right">
<img src="../assets/square_03.png" width="125" height="125">
</div>
