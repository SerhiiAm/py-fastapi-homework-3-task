from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class EmailMixin(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return accounts_validators.validate_email(value.lower())


class PasswordMixin(BaseModel):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class UserRegistrationRequestSchema(EmailMixin, PasswordMixin):
    pass


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr

    model_config = {"from_attributes": True}


class MessageResponseSchema(BaseModel):
    message: str


class UserActivationRequestSchema(EmailMixin):
    token: str


class PasswordResetRequestSchema(EmailMixin):
    pass


class PasswordResetCompleteRequestSchema(EmailMixin, PasswordMixin):
    token: str


class UserLoginRequestSchema(EmailMixin):
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
