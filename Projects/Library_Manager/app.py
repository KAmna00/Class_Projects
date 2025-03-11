import json

class LibraryManager:
    def __init__(self, filename="library.json"):
        self.filename = filename
        self.library = self.load_library()

    def load_library(self):
        """Load library from a JSON file."""
        try:
            with open(self.filename, "r") as file:
                return json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def save_library(self):
        """Save the library to a JSON file."""
        with open(self.filename, "w") as file:
            json.dump(self.library, file, indent=4)

    def add_book(self):
        """Add a new book to the library."""
        title = input("Enter the book title: ")
        author = input("Enter the author: ")
        
        while True:
            year = input("Enter the publication year (YYYY): ")
            if year.isdigit() and len(year) == 4:
                year = int(year)
                break
            else:
                print("❌ Invalid year. Please enter a 4-digit number (e.g., 2021).")
        
        genre = input("Enter the genre: ")
        read_status = input("Have you read this book? (yes/no): ").strip().lower() == "yes"
        
        book = {
            "title": title,
            "author": author,
            "year": year,
            "genre": genre,
            "read": read_status
        }
        self.library.append(book)
        self.save_library()
        print("✅ Book added successfully!\n")

    def remove_book(self):
        """Remove a book by title."""
        title = input("Enter the title of the book to remove: ")
        for book in self.library:
            if book["title"].lower() == title.lower():
                self.library.remove(book)
                self.save_library()
                print("✅ Book removed successfully!\n")
                return
        print("❌ Book not found.\n")

    def search_books(self):
        """Search for a book by title or author."""
        choice = input("Search by: \n1. Title \n2. Author\nEnter your choice: ")
        query = input("Enter the search query: ").strip().lower()
        results = [book for book in self.library if query in book["title"].lower() or query in book["author"].lower()]
        
        if results:
            print("🔎 Matching Books:")
            for book in results:
                print(f"- {book['title']} by {book['author']} ({book['year']}) - {book['genre']} - {'Read' if book['read'] else 'Unread'}")
        else:
            print("❌ No matching books found.\n")

    def display_books(self):
        """Display all books in the library."""
        if not self.library:
            print("📭 Your library is empty.\n")
            return
        print("📚 Your Library:")
        for book in self.library:
            print(f"- {book['title']} by {book['author']} ({book['year']}) - {book['genre']} - {'Read' if book['read'] else 'Unread'}")
        print()

    def display_statistics(self):
        """Show total books and percentage read."""
        total_books = len(self.library)
        read_books = sum(1 for book in self.library if book["read"])
        read_percentage = (read_books / total_books * 100) if total_books > 0 else 0
        print(f"📊 Total books: {total_books}")
        print(f"📖 Percentage read: {read_percentage:.2f}%\n")

    def run(self):
        """Run the main menu loop."""
        while True:
            print("\n📌 Welcome to your Personal Library Manager!")
            print("1. ➕ Add a book")
            print("2. ❌ Remove a book")
            print("3. 🔎 Search for a book")
            print("4. 📚 Display all books")
            print("5. 📊 Display statistics")
            print("6. 🚪 Exit")
            choice = input("Enter your choice: ")
            
            if choice == "1":
                self.add_book()
            elif choice == "2":
                self.remove_book()
            elif choice == "3":
                self.search_books()
            elif choice == "4":
                self.display_books()
            elif choice == "5":
                self.display_statistics()
            elif choice == "6":
                self.save_library()
                print("💾 Library saved to file. Goodbye!")
                break
            else:
                print("❌ Invalid choice. Please try again.\n")

if __name__ == "__main__":
    manager = LibraryManager()
    manager.run()
