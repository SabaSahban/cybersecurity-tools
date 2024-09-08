import re
import pandas as pd


def check_password_strength(password, common_passwords_df):
    # Check common password
    if password in common_passwords_df['password'].values:
        return "Weak: Password is in the common passwords dataset."

    # Check minimum length
    if len(password) < 8:
        return "Weak: Password length should be at least 8 characters."

    # Check maximum length
    max_length = 15
    if len(password) > max_length:
        return f"Weak: Password length exceeds the maximum limit of {max_length} characters."

    # Check blacklist
    blacklist = ["password", "123456", "1234", "admin", "sabasabasaba"]
    if password.lower() in blacklist:
        return "Weak: Password is easily guessable and part of the blacklist."

    # Check complexity
    if not re.search(r"\d", password) or not re.search(r"[A-Z]", password) or not re.search(r"[!@#$%^&*(),.?\":{}|<>]",
                                                                                            password):
        return "Weak: Password should include at least one digit, one uppercase letter, and one special character."

    # Check randomness
    if len(set(password)) < len(password) / 2:
        return "Strong: Password appears to be randomly chosen."

    return "Strong: Password meets recommended security guidelines."


def main():
    common_passwords_df = pd.read_csv('common_passwords.csv')

    while True:
        password = input("Enter your password: ")
        result = check_password_strength(password, common_passwords_df)

        if "Weak" in result:
            print(result)
            print("Try again")
        else:
            print("Password is strong:)")
            break


if __name__ == "__main__":
    main()
