import random
import os

class AES:
    def __init__(self, key):
        self.key = key

    def _pad_message(self, message):
        padding_length = 16 - (len(message) % 16)
        padded_message = message + bytes([padding_length] * padding_length)
        return padded_message

    def _xor_bytes(self, a, b):
        return bytes(x ^ y for x, y in zip(a, b))

    def _split_blocks(self, data, block_size=16):
        return [data[i:i+block_size] for i in range(0, len(data), block_size)]

    def _encrypt_block(self, block):
        return self._xor_bytes(block, self.key)

    def _decrypt_block(self, block):
        return self._xor_bytes(block, self.key)

    def encrypt(self, message):
        padded_message = self._pad_message(message.encode())
        encrypted_blocks = [self._encrypt_block(block) for block in self._split_blocks(padded_message)]
        return b''.join(encrypted_blocks)

    def decrypt(self, ciphertext):
        decrypted_blocks = [self._decrypt_block(block) for block in self._split_blocks(ciphertext)]
        padding_length = decrypted_blocks[-1][-1]
        unpadded_message = b''.join(decrypted_blocks[:-padding_length])
        return unpadded_message.decode()

class Bank:
    def __init__(self):
        self.card_details = {}
        # Sample card details
        self.sample_card_details = {
            "1234567890123456": {
                "details": "John Doe,123 Main St,New York,NY,10001",
                "pin": "1234",  # Example PIN
                "otp": None
            }
        }

    def add_card_details(self, card_number, card_details, pin):
        self.card_details[card_number] = {
            "details": card_details,
            "pin": pin,
            "key": os.urandom(16)  # Generating a random key for each user
        }

    def encrypt_card_details(self, card_number):
        aes = AES(self.card_details[card_number]["key"])
        encrypted_details = aes.encrypt(self.card_details[card_number]["details"])
        return encrypted_details

    def decrypt_card_details(self, card_number, encrypted_details):
        aes = AES(self.card_details[card_number]["key"])
        decrypted_details = aes.decrypt(encrypted_details)
        return decrypted_details

    def process_transaction(self, card_number, entered_pin, entered_otp):
        if card_number in self.card_details:
            if entered_pin == self.card_details[card_number]["pin"]:
                if entered_otp == self.sample_card_details[card_number]["otp"]:
                    return "Transaction successful"
                else:
                    return "Invalid OTP. Transaction failed."
            else:
                return "Invalid PIN. Transaction failed."
        else:
            return "Card not found"

    def verify_user(self, card_number, pin):
        if card_number in self.sample_card_details and self.sample_card_details[card_number]["pin"] == pin:
            return True
        else:
            return False

    def validate_card_details(self, card_number, card_details):
        if card_number in self.sample_card_details and \
           self.sample_card_details[card_number]["details"] == card_details:
            return True
        else:
            return False

    def generate_otp(self):
        return str(random.randint(100000, 999999))  # 6-digit OTP

class User:
    def enter_pin(self):
        return input("Enter your 4-digit PIN: ")

    def enter_otp(self):
        return input("Enter the 6-digit OTP sent to your registered mobile number: ")

class Transaction:
    def __init__(self, bank, user):
        self.bank = bank
        self.user = user

    def swipe_card(self, card_number, transaction_data):
        if card_number in self.bank.card_details:
            print("Card details already verified.")
        else:
            card_details = input("Enter card details (e.g., Name,Address,City,State,Zip): ")
            pin = self.user.enter_pin()  # Prompt user for PIN
            if self.bank.validate_card_details(card_number, card_details):
                if self.bank.verify_user(card_number, pin):
                    otp = self.bank.generate_otp()
                    print("Generated 6-digit OTP:", otp)
                    self.bank.sample_card_details[card_number]["otp"] = otp
                    self.bank.add_card_details(card_number, card_details, pin)
                else:
                    return "Invalid PIN. Transaction failed."
            else:
                return "Invalid card details. Transaction failed."

        encrypted_details = self.bank.encrypt_card_details(card_number)
        print("Encrypted card details:", encrypted_details)
        decrypted_details = self.bank.decrypt_card_details(card_number, encrypted_details)

        entered_otp = self.user.enter_otp()
        result = self.bank.process_transaction(card_number, pin, entered_otp)
        return result

# Example usage
bank = Bank()
user = User()
transaction = Transaction(bank, user)

card_number = input("Enter card number: ")
transaction_result = transaction.swipe_card(card_number, None)
print("Transaction result:", transaction_result)
