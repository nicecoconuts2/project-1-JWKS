from flask import Flask
from jwks.jwks import jwks
from auth.auth import authenticate

app = Flask(__name__)

# Register routes
app.add_url_rule('/.well-known/jwks.json', view_func=jwks)
app.add_url_rule('/auth', view_func=authenticate, methods=['POST'])

if __name__ == '__main__':
    app.run(port=8080)