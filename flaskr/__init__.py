import os

from flask import Flask, Response
from flask_cors import CORS, cross_origin

from .scan import nl80211_scan_json

def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=os.path.join(app.instance_path, 'flaskr.sqlite'),
    )

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # a simple page that says hello
    @app.route('/hello')
    def hello():
        return 'Hello, World!'

    @app.route('/scan')
    @cross_origin()
    def scan():
        data = nl80211_scan_json.run("wlp1s0")
        return Response(data, mimetype="application/json")
#        return nl80211_scan_json.run("wlp1s0")

    return app
