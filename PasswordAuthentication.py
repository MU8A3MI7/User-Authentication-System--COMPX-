import re
import bcrypt

# User class to store user information
class User:
    def __init__(self, username, hashed_password):
        self.username = username
        self.hashed_password = hashed_password

# List to store enrolled users, wear words and breached/common passwords
users = []
swear_words = []
breached_passwords = []

# Read swear words from file.
with open("swearWords.txt") as file:
    swear_words = [line.strip() for line in file]

# Read breached and common passwords from file.
with open('breachedpasswords.txt', 'r') as file:
    data = file.read()
    # Split the passwords by new line
    breached_passwords = data.split()

# Define a function to replace numbers with corresponding letters
def replace_numbers(word):
    number_map = {"0": "o", "1": "i", "2": "z", "3": "e", "4": "a", "5": "s", "6": "g", "7": "t", "8": "b", "9": "g"}
    return "".join([number_map.get(char, char) for char in word])


# Function to validate username against rules
def validate_username(username):
    # Convert username to lowercase for case-insensitive comparison
    username = username.lower()
    
    # Replace numbers with corresponding letters
    username = replace_numbers(username)
    
    # Check if username contains only allowed characters
    if not re.match("^[a-zA-Z0-9_]*$", username):
        return False
    
    # Check if username contains swear words
    if any(word in username for word in swear_words):
        return False
    return True

# Function to validate password against NIST guidelines
def validate_password(password):
    # Password guidelines
    # Minimum length of 12 characters
    # At least one uppercase letter, one lowercase letter, one digit, and one special character
    # No password hints or easily guessable information
    # Not using common or easily guessable passwords
    # No password reuse from previous accounts
    
    # Check password length
    if len(password) < 12:
        return False
    # Check for at least one uppercase letter, one lowercase letter, one digit, and one special character
    if not (any(char.isupper() for char in password) and
            any(char.islower() for char in password) and
            any(char.isdigit() for char in password) and
            any(char in "!@#$%^&*()-_=+{}[]|;:'\",.<>/?`~" for char in password)):
        return False
    # Check for password hints or easily guessable information
    # List of breached and common passwords to be checked are in breached file
    if any(word in password for word in breached_passwords):
        return False
    # Check for password reuse from previous accounts
    if any(bcrypt.checkpw(password.encode('utf-8'), user.hashed_password) for user in users):
        return False
    return True

# Function for user enrollment
def enroll_user():
    # Prompt user for username
    while True:
        username = input("Enter username (letters, numbers, and underscore only): ").lower()
        if validate_username(username):
            break
        else:
            print("Invalid username. Please choose a different username.")
    # Prompt user for password
    while True:
        password = input("Enter password (at least 12 characters, with uppercase, lowercase, digit, and special character): ")
        if validate_password(password):
            # Hash password before storing
            # Generate salt
            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

            # Create new User object and store in users list
            user = User(username, hashed_password)
            users.append(user)
            print("User enrolled successfully.")
            break
        else:
            print("Invalid password. Please choose a stronger password.")

# Function for user verification
def verify_user():
    # Prompt user for username and password
    username = input("Enter username: ").lower()
    password = input("Enter password: ")
    # Hash password for comparison
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    # Check if username and hashed password match in users list
    for user in users:
        if user.username == username and bcrypt.checkpw(password.encode('utf-8'), user.hashed_password):
            print("Welcome, {}!".format(user.username))
            return
    print("Error: Invalid username or password.")



# Main loop for user interaction
while True:
    print("Password-based Authentication System")
    print("1. Enroll new user")
    print("2. Verify user")
    print("3. Exit")
    choice = input("Enter your choice (1/2/3): ")
    if choice == "1":
        enroll_user()
    elif choice == "2":
        verify_user()
    elif choice == "3":
        print("Exiting...")
        break
    else:
        print("Invalid choice. Please try again.")
