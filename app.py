from flask import Flask
from flask import render_template
from flask_mongoengine import MongoEngine

from routes.login import login_blueprint
from routes.register import register_blueprint
from routes.document import sign_document_blueprint
from routes.user import user_blueprint

app = Flask(__name__)
app.register_blueprint(login_blueprint, url_prefix='/login')
app.register_blueprint(register_blueprint, url_prefix='/register')
app.register_blueprint(sign_document_blueprint, url_prefix='/document')
app.register_blueprint(user_blueprint, url_prefix='/user')
app.config['MONGODB_SETTINGS'] = {
    "db": "licenta",
    "host": "mongodb+srv://mariap:pHhOqQlI5YYoZrNW@cluster0.7foql.mongodb.net/?retryWrites=true&w=majority"
}
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'


@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404


db = MongoEngine(app)

if __name__ == '__main__':

    app.run(debug=True)
