from pydantic import BaseModel, EmailStr, Field, AfterValidator

from typing_extensions import Annotated


def validate_password(value: str) -> str:
    import re
    if len(value) < 8:
        raise ValueError("Password must contain at least 8 characters.")
    if not re.search(r'[A-Z]', value):
        raise ValueError("Password must contain at least one uppercase letter.")
    if not re.search(r'[a-z]', value):
        raise ValueError("Password must contain at least one lower letter.")
    if not re.search(r'\d', value):
        raise ValueError("Password must contain at least one digit.")
    if not re.search(r'[@$!%*?&#]', value):
        raise ValueError("Password must contain at least one special character: @, $, !, %, *, ?, #, &.")
    return value


EvenPassword = Annotated[str, AfterValidator(validate_password)]


class UserBase(BaseModel):
    email: EmailStr


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: EvenPassword


class UserActivationRequestSchema(BaseModel):
    email: str
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(UserBase):
    pass


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = Field(default="bearer")


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
