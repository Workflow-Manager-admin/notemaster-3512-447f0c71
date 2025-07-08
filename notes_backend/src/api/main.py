from fastapi import FastAPI, Depends, HTTPException, status, Body, Path
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext

# -- GLOBAL CONFIG AND LIBS --

SECRET_KEY = "supersecretchangeme"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Password context for hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

# -- IN-MEMORY DATA STORES (Replace with DB in production) --

db_users = {}
db_notes = {}
note_id_counter = 1
user_id_counter = 1

# -- MODELS AND SCHEMAS --

# User models
class UserBase(BaseModel):
    username: str = Field(..., min_length=3, description="Unique username")
    email: EmailStr = Field(..., description="User email address")

class UserCreate(UserBase):
    password: str = Field(..., min_length=4, description="Password")

class User(UserBase):
    id: int

class UserInDB(User):
    hashed_password: str

# Token models
class Token(BaseModel):
    access_token: str
    token_type: str

# Note models
class NoteBase(BaseModel):
    title: str = Field(..., min_length=1, description="Title of the note")
    content: str = Field(..., description="Content of the note")

class NoteCreate(NoteBase):
    pass

class NoteUpdate(BaseModel):
    title: Optional[str] = Field(None, description="Updated title")
    content: Optional[str] = Field(None, description="Updated content")

class Note(NoteBase):
    id: int
    owner_id: int
    created_at: datetime
    updated_at: datetime

# -- FASTAPI SETUP --

app = FastAPI(
    title="Notes Backend API",
    version="1.0.0",
    description="Backend for managing notes and users.",
    openapi_tags=[
        {
            "name": "auth",
            "description": "User authentication and registration"
        },
        {
            "name": "notes",
            "description": "CRUD operations for notes"
        }
    ]
)

# Allow CORS for local/dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -- AUTH UTILS --

# PUBLIC_INTERFACE
def get_password_hash(password: str) -> str:
    """Hashes a password."""
    return pwd_context.hash(password)

# PUBLIC_INTERFACE
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against its hashed version."""
    return pwd_context.verify(plain_password, hashed_password)

# PUBLIC_INTERFACE
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Creates a JWT access token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# PUBLIC_INTERFACE
def get_user_by_username(username: str) -> Optional[UserInDB]:
    """Fetch a user by username."""
    for user in db_users.values():
        if user.username == username:
            return user
    return None

# PUBLIC_INTERFACE
def authenticate_user(username: str, password: str) -> Optional[UserInDB]:
    """Authenticate a user credentials."""
    user = get_user_by_username(username)
    if user and verify_password(password, user.hashed_password):
        return user
    return None

# PUBLIC_INTERFACE
async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserInDB:
    """Dependency to get the current logged-in user."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user_by_username(username)
    if user is None:
        raise credentials_exception
    return user

# -- API ROUTES --

@app.get("/", tags=["health"], summary="Healthcheck endpoint")
def health_check():
    """Healthcheck endpoint."""
    return {"message": "Healthy"}

# --- Auth Endpoints ---

@app.post("/auth/register", response_model=User, summary="Register a new user", tags=["auth"])
# PUBLIC_INTERFACE
def register_user(user_in: UserCreate = Body(...)):
    """
    Register a new user.

    - **username**: Unique username
    - **email**: Valid email
    - **password**: Password (min 4 characters)
    """
    global user_id_counter
    if get_user_by_username(user_in.username):
        raise HTTPException(status_code=409, detail="Username already registered")
    for user in db_users.values():
        if user.email == user_in.email:
            raise HTTPException(status_code=409, detail="Email already registered")
    hashed_password = get_password_hash(user_in.password)
    user = UserInDB(
        id=user_id_counter,
        username=user_in.username,
        email=user_in.email,
        hashed_password=hashed_password,
    )
    db_users[user_id_counter] = user
    user_id_counter += 1
    return User(**user.model_dump())

@app.post("/auth/token", response_model=Token, summary="Get JWT token for user", tags=["auth"])
# PUBLIC_INTERFACE
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Obtain a JWT token for authentication. Submit username and password.
    """
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/auth/me", response_model=User, summary="Get current authenticated user", tags=["auth"])
# PUBLIC_INTERFACE
async def get_me(current_user: UserInDB = Depends(get_current_user)):
    """
    Fetches details of the currently authenticated user.
    """
    return User(**current_user.model_dump())

# --- Notes Endpoints ---

@app.get("/notes", response_model=List[Note], summary="List notes for current user", tags=["notes"])
# PUBLIC_INTERFACE
def list_notes(current_user: UserInDB = Depends(get_current_user)):
    """
    Returns all notes belonging to current authenticated user.
    """
    return [
        note
        for note in db_notes.values()
        if note.owner_id == current_user.id
    ]

@app.post("/notes", response_model=Note, status_code=201, summary="Create a new note", tags=["notes"])
# PUBLIC_INTERFACE
def create_note(note_in: NoteCreate, current_user: UserInDB = Depends(get_current_user)):
    """
    Create a new note for current user.
    """
    global note_id_counter
    now = datetime.utcnow()
    note = Note(
        id=note_id_counter,
        owner_id=current_user.id,
        title=note_in.title,
        content=note_in.content,
        created_at=now,
        updated_at=now,
    )
    db_notes[note_id_counter] = note
    note_id_counter += 1
    return note

@app.put("/notes/{note_id}", response_model=Note, summary="Update a note", tags=["notes"])
# PUBLIC_INTERFACE
def update_note(
    note_id: int = Path(..., description="ID of the note to update"),
    note_update: NoteUpdate = Body(...),
    current_user: UserInDB = Depends(get_current_user),
):
    """
    Update an existing note (partial or full update) belonging to the user.
    """
    note = db_notes.get(note_id)
    if not note or note.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Note not found")
    update_data = note_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(note, field, value)
    note.updated_at = datetime.utcnow()
    db_notes[note_id] = note
    return note

@app.delete("/notes/{note_id}", status_code=204, summary="Delete a note", tags=["notes"])
# PUBLIC_INTERFACE
def delete_note(
    note_id: int = Path(..., description="ID of the note to delete"),
    current_user: UserInDB = Depends(get_current_user),
):
    """
    Delete a note by its ID (must belong to current user).
    """
    note = db_notes.get(note_id)
    if not note or note.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Note not found")
    del db_notes[note_id]
    return

@app.get("/notes/{note_id}", response_model=Note, summary="Get a specific note", tags=["notes"])
# PUBLIC_INTERFACE
def get_note(
    note_id: int = Path(..., description="ID of the note to fetch"),
    current_user: UserInDB = Depends(get_current_user),
):
    """
    Get a specific note by ID (must belong to current user).
    """
    note = db_notes.get(note_id)
    if not note or note.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Note not found")
    return note

# --- Additional API doc endpoint for OpenAPI/Swagger usage note for frontend integration ---

@app.get("/docs/websocket-help", tags=["health"], include_in_schema=True)
def websocket_help():
    """
    There are no websocket endpoints for this API (REST only).
    """
    return {"detail": "This API is RESTful and does not expose websockets."}

