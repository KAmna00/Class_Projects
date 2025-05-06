class Employee:
    def __init__(self, name, salary, ssn):
        self.name = name           # Public
        self._salary = salary     # Protected (convention)
        self.__ssn = ssn          # Private (name mangling)

emp = Employee("John", 50000, "123-45-6789")
print(emp.name)            # Accessible
print(emp._salary)         # Accessible (but should be treated as protected)
try:
    print(emp.__ssn)       # Raises AttributeError (private)
except AttributeError:
    print("Cannot access private attribute __ssn directly.")