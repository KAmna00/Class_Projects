class Book:
    total_books = 0

    @classmethod
    def increment_total(cls):
        cls.total_books += 1

Book.increment_total()
Book.increment_total()
print(f"Total books: {Book.total_books}")