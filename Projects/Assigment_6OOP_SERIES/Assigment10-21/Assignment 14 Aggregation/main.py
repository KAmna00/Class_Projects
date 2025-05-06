class Employee:
    def __init__(self, name):
        self.name = name

class Department:
    def __init__(self, name, employee=None):
        self.name = name
        self.employee = employee  # Aggregation (Department "uses" Employee)

emp = Employee("Ali")
dept = Department("IT", emp)
print(f"{dept.employee.name} works in {dept.name}.")