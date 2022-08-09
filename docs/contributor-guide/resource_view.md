# ResourceView

A `ResourceView` is an object which is an instance of a `ViewableResourceTag` and may contain
methods and attributes. A `Resource` tagged with that `ViewableResourceTag` may be analyzed
for the information necessary to create an instance of that `ViewableResourceTag` - this means
calling analyzers which produce all of the attributes defined for that tag.

## Motivation

Many ResourceTags represent abstractions of firmware artifacts which certainly have some
information associated with them. For example, an Instruction certainly has a virtual address, a
size, and a mnemonic. In OFRAK these could be represented as individual ResourceAttributes types,
 which are each analyzed individually. But this presents a couple of problems:
 1) It is not obvious which attributes a particular tag can be expected to have, since they are
 necessarily decoupled.
 2) If attributes are divided into individual classes (which is desirable for consistency when
 dealing with a particular abstraction, e.g. every resource that has a virtual address should
 represent that address in the same way) then to represent all of the "certain" attributes of a
 given tag, multiple instances of attributes and/or a container to hold them are needed.
 3) Since the certainty that resources with a given tag have some specific attributes is not
 actually enforced, it is not a guarantee and this creates the need to handle cases where those
 attributes are not present. In order to be guaranteed the presence of those attributes, they
 should be fetched through `Resource.analyze(...)` however this is an async call which
 may generate some I/O. For debugging (and in general for easier reasoning) it would be much
 easier if all of these "certain" attributes could be analyzed together and stored together in a
 simple container.

Additionally, there are cases where it is useful to have a representation of a resource without
actually creating a proper Resource. At the very least this might represent all of the attributes
of that resource. This avoids the unnecessary creating & deleting of temporary resources. Instead, 
a familiar representation would be created in the meantime, and
turned into a proper Resource once finalized.

## Design

The `ResourceView` class is merely the base class to inherit from in order to create a new viewable
tag. A `ViewableResourceTag` is equivalent to a `ResourceTag` and can be used in all the same
ways. In addition, if a resource is tagged with a particular `ViewableResourceTag`, a client
can get a view instance of the resource. This view instance will be an instance of that
particular `ViewableResourceTag` type, with all of the attributes that tag should have. The class
definition of the tag defines what these attributes are, as well as any methods also available to
the view.

A view may also contain an instance of the Resource it is "viewing": When a client calls
`v = r.view_as(T)` the returned view `v` of type `T` will have an attribute `v.resource` which
returns `r`. This attribute is optional though; views can be created independently of any
`Resource` by instantiating them with the class's normal dataclass constructor.

It's easiest to understand the `ResourceView` by first imagining it totally independently from the
`Resource`. On that level it is pretty simple: It is just a dataclass, and it represents some
specific firmware abstraction. Now add in that one can convert easily back and forth between the
`ResourceView` and the `Resource` - the former is specific to one firmware abstraction, and the
latter is a generic interface for all firmware artifacts OFRAK works with.


## When to Use

When should one define a tag as a `ViewableResourceTag` (by inheriting from `ResourceView`)
instead of a simple `ResourceTag`?
* It's a good idea to make a tag viewable when any resource with this tag should certainly have
some attributes, and any resource with those attributes should certainly be considered an
instance of that tag. A viewable tag is a purposeful coupling of attributes to a tag, so you
should be sure that is what you want to do.
* Another case it's a good idea to make a tag viewable is when there is some frequent functionality
 you want to expose in a method of that tag. As mentioned before, it is a common pattern to write
 methods for a tag which wrap queries to find related resources.
* If you make a tag viewable because you want to write methods for it, be careful to not throw in
attributes to that class without good reason. They should still satisfy the "certainly" clauses
under the first bullet.

## Notes on Metaclass Terminology

`ResourceTag` and `ViewableResourceTag` are both metaclasses. This means that an instance of
either one is a class. `ResourceView` is a class, which is an instance of `ViewableResourceTag`.
Then an instance of `ResourceView` is an object - the view itself.

```python3
type(view_instance) is ResourceView
type(ResourceView) is ViewableResourceTag
```

Since tags are classes, when we talk about the tags in the context of (for example) a list, we
say that list has type `List[ResourceTag]`. Just like a list of type `List[Wrench]` contains
instances of `Wrench`, our tag list contains instances of `ResourceTag` - each of which happens
to be a class object. It's similar to typing `List[Type[SomeClassWithMetaclassResourceTag]]`.

<div align="right">
<img src="../assets/square_01.png" width="125" height="125">
</div>
