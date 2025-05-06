class Bank:
    bank_name = "ABC Bank"

    @classmethod
    def update_bank_name(cls, new_name):
        cls.bank_name = new_name

b1 = Bank()
b2 = Bank()
print(Bank.bank_name)
Bank.update_bank_name("XYZ Bank")
print(b1.bank_name)
print(b2.bank_name)