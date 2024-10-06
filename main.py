import httpx
from fastapi import FastAPI, HTTPException, Request
from pymongo import MongoClient
from pydantic import BaseModel
from bson import ObjectId
from typing import List, Optional
from fastapi.responses import RedirectResponse
from utility import generate_shortURL_code, generate_api_key, hash_password, verify_password
from modals.modals import URL, ResponseModel, User, CreateShortURLPayload, SignupPayload, LoginPayload, UserResponseModal
from authlib.integrations.requests_client import OAuth2Session
from authlib.integrations.starlette_client import OAuth
from starlette.middleware.sessions import SessionMiddleware


from provider.github import CLIENT_ID, CLIENT_SECRET, REDIRECT_URI


app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key="ablackcat")

# MongoDB connection
client = MongoClient(
    "#########")
db = client.url_shortner
urlsCollection = db.urls
userCollection = db.users

print(client)

# oauth = OAuth2Session(client_id=CLIENT_ID,
#                       client_secret=CLIENT_SECRET, redirect_uri=REDIRECT_URI)

oauth = OAuth()
oauth.register(
    name='github',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    authorize_url='https://github.com/login/oauth/authorize',
    authorize_params=None,
    access_token_url='https://github.com/login/oauth/access_token',
    access_token_params=None,
    refresh_token_url=None,
    redirect_uri=REDIRECT_URI,
    client_kwargs={'scope': 'user:email'}
)


def generate_unique_short_code():
    maxRepeatCount = 10
    while maxRepeatCount is not 0:
        short_code = generate_shortURL_code()
        maxRepeatCount = maxRepeatCount - 1
        if not urlsCollection.find_one({"shortURL": short_code}):
            return short_code

    return None


# =====================Auth API=========================================


@app.get("/github/login")
async def githubLogin(request: Request):
    redirect_uri = request.url_for("callback")
    return await oauth.github.authorize_redirect(request, redirect_uri)


@app.get("/github/callback")
async def callback(request: Request):
    token = await oauth.github.authorize_access_token(request)
    accessToken = token['access_token']

    if accessToken is None:
        return {
            "msg": "Invalid Credential",
            "success": False
        }
    headers = {
        'Accept': 'application/json',
        'Authorization': f'Bearer {accessToken}'
    }
    async with httpx.AsyncClient() as client:
        user_info = await client.get("https://api.github.com/user", headers=headers)
        user = user_info.json()

    print(user)
    # return user
    user_email = user['notification_email']
    user_name = user['name']

    result = userCollection.find_one(
        {"email": user_email})
    if result is None:
        apiKey = generate_api_key()
        newUser = User(
            name=user_name,
            email=user_email,
            password=accessToken,
            provider="github",
            apiKey=apiKey,
            consumed=0
        )

        result = userCollection.insert_one(newUser.dict())
        print(result)
        response = {
            "msg": "You are successfully registered."
        }
        return response

    user = {
        "userId": str(result['_id']),
        "name": result["name"],
        "email": result["email"],
        "apiKey": result["apiKey"],
        "consumed": result["consumed"]
    }

    response = {
        "success": True,
        "data": user
    }

    return response


@app.post("/signup")
async def create_user(user: SignupPayload):
    generatedApiKey = generate_api_key()
    hasedPassword = hash_password(user.password)
    newUser = User(
        name=user.name,
        email=user.email,
        password=hasedPassword,
        apiKey=generatedApiKey,
        consumed=0
    )
    result = userCollection.insert_one(newUser.dict())
    print(result)
    response = {
        "msg": "You are successfully registered."
    }
    return response


@app.post("/login")
async def create_user(user: LoginPayload):
    # Create a invalid user response flag
    result = userCollection.find_one(
        {"email": user.email})
    if result is None:
        return {
            "success": False,
            "msg": "Incorrect credentials"
        }

    isPasswordMatched = verify_password(result['password'], user.password)

    if isPasswordMatched is False:
        return {
            "success": False,
            "msg": "Incorrect credentials"
        }

    user = {
        "userId": str(result['_id']),
        "name": result["name"],
        "email": result["email"],
        "apiKey": result["apiKey"],
        "consumed": result["consumed"]
    }

    response = {
        "success": True,
        "data": user
    }
    return response


# ============ URL APIs ================================

# get long url
@app.get("/{tag}/{short_url}")
async def get_url(tag: str, short_url: str):
    urlData = urlsCollection.find_one({"shortURL": short_url})
    print(urlData)
    url = urlData["longURL"]
    return RedirectResponse(url)


# create short url
@app.post("/create-url")
async def create_url(url: CreateShortURLPayload, response_model=None):
    short_url = generate_unique_short_code()

    # check if shrt_url is None
    if short_url is None:
        response = {
            "success": False,
            "message": "Something went wrong. Please try later."
        }

        return response

    # Create an instance of the URL model
    user = userCollection.find_one({"apiKey": url.apiKey})

    print("user")
    print(user)
    if user is None:
        response = {
            "success": False,
            "message": "Invalid user or api key."
        }

        return response

    if user["consumed"] > 50:
        response = {
            "success": False,
            "message": "Limit is exceeded."
        }

        return response

    url_instance = URL(
        longURL=url.longURL,
        shortURL=short_url,
        tag=url.tag,
        userId=url.userId
    )

    # Convert the instance to a dictionary
    url_dict = url_instance.dict()

    result = urlsCollection.insert_one(url_dict)

    # update the consumed value into user document

    query = {"apiKey": user['apiKey']}
    new_values = {"$set": {"consumed": user['consumed'] + 1}}

    userCollection.update_one(query, new_values)
    tiny_url = "http://localhost:8000/"+url.tag+"/"+short_url
    response = ResponseModel(
        success=True,
        url=tiny_url,
        message="URL successfully shortened",
    )
    return response
