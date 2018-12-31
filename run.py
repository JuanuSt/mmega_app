import mmega
from mmega import app as application

# Start
if __name__ == '__main__':
    application.run(host='0.0.0.0', port=5000, threaded=True)
    application.app_context().push()

