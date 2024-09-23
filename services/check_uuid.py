import uuid

def number_to_uuid(num):
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, str(num)))

# Example: Generate a UUID from a given number
given_number = 1706006475584
uuid_string = number_to_uuid(given_number)
print(uuid_string)


# does it will generate same uuid for same number?
