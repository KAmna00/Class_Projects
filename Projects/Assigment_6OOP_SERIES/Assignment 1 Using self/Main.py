class Student:
    def __init__(self, name, marks):
        self.name = name
        self.marks = marks

    def display(self):
        print(f"Name: {self.name}\nMarks: {self.marks}")

s1 = Student("Ali", 87)
s1.display()