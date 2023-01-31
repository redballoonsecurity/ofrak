import functools
import inspect


def auto_validate_state(validator_function):
    """
    Class decorator for services or other objects with complex internal state. Used to create
    classes with methods that run a state validation function after every (public) method call.

    Public methods are detected as any callable whose name does not start with an underscore ("_").

    Example usage:
    def validator_function(clasS_instance):
        # validation logic
        ...


    @auto_validate_state(validator_function)
    class AutoValidatingImplementation(ClassWithInternalState):
        pass

    An instance of AutoValidatingImplementation now runs validator_function on itself after every
    method call.

    :param validator_function:

    :return:
    """

    def decorator(cls):
        def factory(method):
            if inspect.iscoroutinefunction(method):

                @functools.wraps(method)
                async def wrapped_method(self, *args, **kwargs):
                    result = await method(self, *args, **kwargs)
                    validator_function(self)

                    return result

            else:

                @functools.wraps(method)
                def wrapped_method(self, *args, **kwargs):
                    result = method(self, *args, **kwargs)
                    validator_function(self)

                    return result

            return wrapped_method

        methods = [
            (attr_name, getattr(cls, attr_name))
            for attr_name in dir(cls)
            if not attr_name.startswith("_") and callable(getattr(cls, attr_name))
        ]
        for method_name, method in methods:
            setattr(cls, method_name, factory(method))

        return cls

    return decorator
