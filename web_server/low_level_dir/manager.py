import time

def check_password(input_password):
    actual_password = "nice_work!"
    # Vulnerable comparison with intentional delay
    for i in range(len(input_password)):
        if i >= len(actual_password) or input_password[i] != actual_password[i]:
            return False
        time.sleep(0.1)
    if len(input_password) != len(actual_password):
        return False
    return True

def password_manager(input_password):
    if check_password(input_password):
        return "Correct password!"
    else:
        return "Incorrect password."

if __name__ == "__main__":
    test_password = input()
    result = password_manager(test_password)
    print(result)
