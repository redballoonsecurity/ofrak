from synthol.injector import DependencyInjector

import ofrak
import ofrak_components


def bind_dependencies(injector: DependencyInjector):
    injector.discover(ofrak)
    injector.discover(ofrak_components)
