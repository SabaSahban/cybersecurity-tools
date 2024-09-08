import string
import time
import itertools


def find_password_in_generated_passwords(generated_strings, target_string, first_letter):
    for i, generated_string in enumerate(generated_strings):
        print(first_letter + generated_string)
        if generated_string == target_string:
            print(f"Found the password with {i + 1} tries.")
            return


def standard_mode():
    password_length = int(input("Enter the length of the password: "))
    search_space = input("Enter the search space"
                         " (1 for numbers, (2 for lowercase letters,"
                         " (3 for lowercase letters and numbers,"
                         " (4 for numbers, letters, lowercase and uppercase, and characters")
    if search_space == "1":
        search_space = string.digits
    elif search_space == "2":
        search_space = string.ascii_lowercase
    elif search_space == "3":
        search_space = string.ascii_lowercase + string.digits
    elif search_space == "4":
        search_space = string.digits + string.ascii_letters + string.punctuation
    else:
        print("Invalid search space.")
        return

    password = input("Enter the password: ")

    if len(password) != password_length or not all(char in search_space for char in password):
        print("Invalid password.")
        return

    start_time = time.time()

    possible_strings = [''.join(p) for p in itertools.product(search_space, repeat=password_length)]
    find_password_in_generated_passwords(possible_strings, password, "")

    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"Elapsed time: {elapsed_time} seconds")

    return possible_strings


def search_by_first_char():
    first_char = input("Enter the first character of the password: ")
    password_length = int(input("Enter the length of the password: "))
    search_space = input("Enter the search space"
                         " (1 for numbers, (2 for lowercase letters,"
                         " (3 for lowercase letters and numbers,"
                         " (4 for numbers, letters, lowercase and uppercase, and characters")
    if search_space == "1":
        search_space = string.digits
    elif search_space == "2":
        search_space = string.ascii_lowercase
    elif search_space == "3":
        search_space = string.ascii_letters + string.digits
    elif search_space == "4":
        search_space = string.digits + string.ascii_letters + string.punctuation
    else:
        print("Invalid search space.")
        return

    password = input("Enter the password: ")

    if len(password) != password_length or not all(char in search_space for char in password):
        print("Invalid password.")
        return

    password = password[1:]

    start_time = time.time()

    possible_strings = [''.join(p) for p in itertools.product(search_space, repeat=password_length - 1)]
    find_password_in_generated_passwords(possible_strings, password, first_char)

    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"Elapsed time: {elapsed_time} seconds")

    return possible_strings


def search_by_k_chars():
    password_length = int(input("Enter the length of the password: "))
    search_space = input("Enter the search space"
                         " (1 for numbers, (2 for lowercase letters,"
                         " (3 for lowercase letters and numbers,"
                         " (4 for numbers, letters, lowercase and uppercase, and characters")
    known_characters = input("Enter the known characters: ")

    if search_space == "1":
        search_space = string.digits
    elif search_space == "2":
        search_space = string.ascii_lowercase
    elif search_space == "3":
        search_space = string.ascii_lowercase + string.digits
    elif search_space == "4":
        search_space = string.digits + string.ascii_letters + string.punctuation
    else:
        print("Invalid search space.")
        return

    password = input("Enter the password: ")

    if len(password) != password_length or not all(char in search_space for char in password):
        print("Invalid password.")
        return

    start_time = time.time()

    possible_strings = generate_permutations_with_known_chars(password_length, known_characters, search_space)

    find_password_in_generated_passwords(possible_strings, password, "")

    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"Elapsed time: {elapsed_time} seconds")

    return possible_strings


def generate_permutations_with_known_chars(length, known_chars, search_space):
    remaining_chars = [char for char in search_space if char not in known_chars]

    permutations_remaining = list(itertools.permutations(remaining_chars, length - len(known_chars)))

    result_permutations = []
    for perm in permutations_remaining:
        for known_char_positions in itertools.permutations(range(length), len(known_chars)):
            current_permutation = list(perm)
            for i, pos in enumerate(known_char_positions):
                current_permutation.insert(pos, known_chars[i])
            result_permutations.append(''.join(current_permutation))

    return result_permutations


def main():
    search_mode = int(input(
        "Enter the search mode (1 for standard, 2 for search by first character, 3 for search by k characters): "))

    if search_mode == 1:
        standard_mode()
    elif search_mode == 2:
        search_by_first_char()
    elif search_mode == 3:
        search_by_k_chars()
    else:
        print("Invalid search mode.")


if __name__ == "__main__":
    main()
