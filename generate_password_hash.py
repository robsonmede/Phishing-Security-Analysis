from getpass import getpass

from argon2 import PasswordHasher


def main():
    password = getpass("Digite a nova senha: ")
    confirmation = getpass("Confirme a nova senha: ")

    if not password:
        raise SystemExit("A senha não pode ficar vazia.")

    if password != confirmation:
        raise SystemExit("As senhas não coincidem.")

    if len(password) < 12:
        raise SystemExit(
            "Use uma senha com pelo menos 12 caracteres."
        )

    password_hasher = PasswordHasher(
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        salt_len=16,
    )

    print("\nHash Argon2:")
    print(password_hasher.hash(password))


if __name__ == "__main__":
    main()
