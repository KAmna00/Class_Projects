class Logger:
    def __init__(self):
        print("Logger initialized. Ready to log messages.")

    def __del__(self):
        print("Logger destroyed. Cleanup complete.")

logger = Logger()
del logger