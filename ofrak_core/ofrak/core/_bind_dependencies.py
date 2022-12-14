from synthol.injector import DependencyInjector

import ofrak


def bind_dependencies(injector: DependencyInjector):
    injector.discover(ofrak)
