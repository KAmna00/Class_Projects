class Engine:
    def start(self):
        print("Engine started.")

class Car:
    def __init__(self):
        self.engine = Engine()  # Composition (Car "has-a" Engine)

    def start(self):
        self.engine.start()

car = Car()
car.start()