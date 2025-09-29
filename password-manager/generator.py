import random
import string
from passmanager import generate_complex_password  # Import the generate_complex_password function


# Function to generate a random password
def generate_random_names(length=8):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))


# Generate 10,000 passwords and save them to "test.txt"
def generate_and_save_passwords():
    simple_password = "0000"
    with open("test.txt", "w") as file:
        for _ in range(10000):
            random_password = generate_random_names()
            complex_password = generate_complex_password(simple_password, random_password)
            file.write(complex_password + "\n")


if __name__ == "__main__":
    generate_and_save_passwords()
