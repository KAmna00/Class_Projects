def add_method(cls):
    def say_hello(self):
        return f"Hello from {self.name}!"
    cls.greet = say_hello
    return cls

@add_method
class Person:
    def __init__(self, name):
        self.name = name

p = Person("Ali")
print(p.greet())