import requests
import time

url = "http://192.168.0.143:8001/"  # Replace with the URL of the server you want to send requests to

def send_request():
    try:
        response = requests.get(url)
        # Process the response as needed
        print(f"Status Code: {response.status_code}")
    except requests.RequestException as e:
        print(f"Request failed: {e}")

# Set the interval between requests in seconds
interval = 5

while True:
    send_request()
    # time.sleep(interval)
