class Person:
    def __init__(self, name):
        self.name = name

class Teacher(Person):
    def __init__(self, name, subject):
        super().__init__(name)  # Initialize parent class
        self.subject = subject

teacher = Teacher("Ms. Sara", "Math")
print(f"{teacher.name} teaches {teacher.subject}.")