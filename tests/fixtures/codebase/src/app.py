def login(user):
    """Autentica um usuário fictício da fixture."""
    if not user:
        raise ValueError("login exige usuário")
    return user
