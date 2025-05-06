class InvalidAgeError(Exception):
    """Exception raised for invalid age values.
    
    Attributes:
        age: The invalid age that caused the error
        message: Explanation of the error
    """
    
    def __init__(self, age: int, message: str = "Age must be at least 18"):
        """Initialize the exception.
        
        Args:
            age: The invalid age value
            message: Custom error message (default provided)
        """
        self.age = age
        self.message = message
        super().__init__(self.message)
    
    def __str__(self) -> str:
        """String representation of the error."""
        return f"{self.message} (got {self.age})"

class AgeValidator:
    """Utility class for age validation."""
    
    MIN_AGE = 18
    MAX_AGE = 120
    
    @classmethod
    def validate(cls, age: int) -> bool:
        """Validate an age value.
        
        Args:
            age: The age to validate
            
        Returns:
            True if age is valid
            
        Raises:
            InvalidAgeError: If age is outside valid range
            TypeError: If age is not an integer
        """
        if not isinstance(age, int):
            raise TypeError(f"Age must be an integer (got {type(age).__name__})")
        
        if age < cls.MIN_AGE:
            raise InvalidAgeError(age, f"Age must be at least {cls.MIN_AGE}")
        elif age > cls.MAX_AGE:
            raise InvalidAgeError(age, f"Age must be less than {cls.MAX_AGE}")
        
        return True

# Demonstration
test_ages = [16, 25, "thirty", 150, 21]

for age in test_ages:
    try:
        AgeValidator.validate(age)
        print(f"✅ Valid age: {age}")
    except InvalidAgeError as e:
        print(f"❌ Invalid age: {e}")
    except TypeError as e:
        print(f"⚠️ Type error: {e}")

# Output:
# ❌ Invalid age: Age must be at least 18 (got 16)
# ✅ Valid age: 25
# ⚠️ Type error: Age must be an integer (got str)
# ❌ Invalid age: Age must be less than 120 (got 150)
# ✅ Valid age: 21
#NOTES:
#You made your own error. Now you can raise it if rules aren’t followed.
#Here: “No under 18s allowed!”