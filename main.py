from fastapi import FastAPI, Depends, HTTPException, status, Header
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import datetime, timedelta
import requests
from pydantic import BaseModel
from typing import Optional

# -----------------------------------------------------------------------------
# Configuration and Constants
# -----------------------------------------------------------------------------

# SECRET_KEY used to sign the JWT tokens. In a real application, store this securely!
SECRET_KEY = "your_super_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 525600  # 1 year

# Static API Key that the client must send in a custom header (e.g., "X-API-KEY")
API_KEY = "my_static_api_key"

# Currency symbols mapping
CURRENCY_SYMBOLS = {
    'USD': '$',
    'EUR': '€',
    'GBP': '£',
    'JPY': '¥',
    'INR': '₹',
    'AUD': 'A$',
    'CAD': 'C$',
    'CHF': 'Fr',
    'CNY': '¥',
    'NZD': 'NZ$'
}

# -----------------------------------------------------------------------------
# Pydantic Models
# -----------------------------------------------------------------------------

class Token(BaseModel):
    access_token: str
    token_type: str

class User(BaseModel):
    username: str

# -----------------------------------------------------------------------------
# OAuth2 and Dependency Functions for JWT Authentication
# -----------------------------------------------------------------------------

# This will look for an Authorization header with a Bearer token.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """
    Dependency function that validates the JWT token passed in the Authorization header.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # Decode the JWT token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        user = User(username=username)
    except JWTError:
        raise credentials_exception
    return user

def verify_api_key(x_api_key: str = Header(...)) -> None:
    """
    Dependency function that validates the API Key sent in the header 'X-API-KEY'.
    """
    if x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API Key")

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Utility function to create a JWT token.
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + (
        expires_delta if expires_delta else timedelta(minutes=15)
    )
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# -----------------------------------------------------------------------------
# Initialize FastAPI Application
# -----------------------------------------------------------------------------

app = FastAPI(
    title="Live Currency Converter API",
    description="This API converts currencies using live data from exchangerate.host. "
    "It uses JWT Bearer Token and API Key authentication.",
    version="1.0",
)

# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------

@app.post("/login", response_model=Token, summary="Login to get a JWT token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Dummy login endpoint.

    **Credentials (for testing):**
    - **username:** testuser
    - **password:** testpassword

    Returns a JWT token that must be used in the Authorization header (Bearer token)
    when calling protected endpoints.
    """
    # In a real application, validate the user credentials against your user store.
    if form_data.username != "testuser" or form_data.password != "testpassword":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": form_data.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/convert", summary="Convert currency amounts using live exchange rates")
def convert_currency(
    from_currency: str,
    to_currency: str,
    amount: float,
    current_user: User = Depends(get_current_user),
    api_key: None = Depends(verify_api_key),
):
    """
    Convert a given amount from one currency to another using live exchange rates.

    **Query Parameters:**
    - **from_currency:** The source currency code (e.g., USD).
    - **to_currency:** The target currency code (e.g., EUR).
    - **amount:** The amount to convert.

    **Authentication:**
    - **JWT Bearer Token:** Obtainable via the `/login` endpoint.
    - **API Key:** Must be provided in the `X-API-KEY` header.

    **Example Request:**
    ```
    GET /convert?from_currency=USD&to_currency=EUR&amount=100
    Headers:
      Authorization: Bearer <your_jwt_token>
      X-API-KEY: my_static_api_key
    ```
    """
    url = f"https://api.exchangerate-api.com/v4/latest/{from_currency.upper()}"
    response = requests.get(url)

    if response.status_code != 200:
        raise HTTPException(status_code=500, detail="Error fetching conversion rate")

    data = response.json()
    rates = data.get("rates", {})
    target_rate = rates.get(to_currency.upper())

    if not target_rate:
        raise HTTPException(status_code=400, detail="Invalid currency codes")

    converted_amount = amount * target_rate
    currency_symbol = CURRENCY_SYMBOLS.get(to_currency.upper(), to_currency.upper())
    formatted_result = f"{currency_symbol}{converted_amount}"

    result = {
        "success": True,
        "from": from_currency.upper(),
        "to": to_currency.upper(),
        "amount": amount,
        "result": converted_amount,
        "formatted_result": formatted_result,
        "rate": target_rate,
    }
    return result

# -----------------------------------------------------------------------------
# Run the Application (For local testing)
# -----------------------------------------------------------------------------

# You can run the app with the following command:
# uvicorn main:app --reload
