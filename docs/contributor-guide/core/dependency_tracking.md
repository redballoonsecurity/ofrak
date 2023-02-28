# OFRAK Dependency Tracking

When a component adds attributes to a resource, OFRAK also records how other Resources were
accessed in the component. This allows OFRAK to track that the modified resources
'depend on' the accessed resources, and appropriately update the modified resources if the
accessed resource is later changed.

OFRAK tracks only two specific types of dependencies:
1. Resource A's attributes X 'depend on' an attribute Y of resources B. Resource A's
attributes X will be invalidated when resource B's attributes Y changes.
2. Resource A's attributes X 'depend on' a range (Y,Z) of resource B's data. Resource A's
attributes X will be invalidated when resource B's has a data patch overlapping with (Y,Z)
applied to it.

Attributes being invalidated simply means that when requested through a `Resource.analyze`
or `Resource.view_as`, an Analyzer will be run to refresh the attributes, even if the
attributes already exist.

TODO: Validate the below and what it is saying??
Whenever a [Modifier][ofrak.component.modifier.Modifier] is run, these resource attribute
dependencies are invalidated so as to force analysis to be rerun.

All of this is facilitated by storing data structures on the dependant resources about
which other resources depend on them and how. To use the terminology of the examples above,
resource B stores the information that resource A's attributes X depend on its
(resource B's) attributes Y, or data range (Y,Z), or even both.
