## Flask restful api

### Installation

```bash
pip install -r requirements.txt
```

### Run

```bash
python app.py
```

### auto-migrate add

### User database 

#### id, email, username, password(hash), confirmed email(true or false)


### API

#### /register

##### POST

```json
{
    "email": "email",
    "username": "username",
    "password": "password"
}
```

#### /login

##### POST

```json
{
    "email_or_username": "email_or_username",
    "password": "password"
}
```

#### /reset_password_request

##### POST

```json
{
    "email": "email"
}
```

#### /reset_password

##### POST
```json
{
    "token": "token",
    "password": "password"
}
```

#### /confirm

##### GET

yourlink/confirm/token

