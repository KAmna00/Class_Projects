def log_function(func):
    def wrapper(*args, **kwargs):
        print(f"Calling {func.__name__}...")
        return func(*args, **kwargs)
    return wrapper

@log_function
def greet(name):
    print(f"Hello, {name}!")

greet("Ali")