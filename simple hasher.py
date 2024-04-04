import hashlib

def hash_text(text):
  """Hashes the provided text using SHA-256 algorithm.

  Args:
      text: The text to be hashed.

  Returns:
      A string containing the hexadecimal representation of the hash.
  """

  # Encode the text as bytes before hashing
  encoded_text = text.encode()
  hashed_bytes = hashlib.sha256(encoded_text)

  # Convert the hash bytes to a hexadecimal string
  return hashed_bytes.hexdigest()

if __name__ == "__main__":
  # Get text input from the user
  text_to_hash = input("Enter the text to hash: ")

  # Hash the text and display the result
  hashed_text = hash_text(text_to_hash)
  print(f"The hash of '{text_to_hash}' is: {hashed_text}")
  input("Press Enter to close...")
