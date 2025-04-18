SPECIAL_CHARS = {'!', '@', '#', '$', '%', '^', '&', '(', ')', '-', '_', '='}

# Function 1: Extract credentials from URL-encoded form string (without using urllib)
def extract_credentials(request):
    body = request.get_data(as_text=True)  # Raw URL-encoded string like "username=abc&password=123%21"
    creds = {}

    key = ""
    value = ""
    is_key = True
    i = 0
    while i < len(body):
        char = body[i]

        if char == '=':
            is_key = False
        elif char == '&':
            creds[key] = value
            key = ""
            value = ""
            is_key = True
        elif char == '%':
            hex_val = body[i+1:i+3]
            decoded_char = chr(int(hex_val, 16))
            if is_key:
                key += decoded_char
            else:
                value += decoded_char
            i += 2
        else:
            if is_key:
                key += char
            else:
                value += char
        i += 1

    if key:
        creds[key] = value

    return [creds.get("username", ""), creds.get("password", "")]


# Function 2: Validate password against 6 rules
def validate_password(password):
    if len(password) < 8:
        return False

    has_upper = has_lower = has_digit = has_special = False

    for char in password:
        if char.islower():
            has_lower = True
        elif char.isupper():
            has_upper = True
        elif char.isdigit():
            has_digit = True
        elif char in SPECIAL_CHARS:
            has_special = True
        else:
            return False  # Invalid character

    return all([has_upper, has_lower, has_digit, has_special])
