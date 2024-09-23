import json

data = {
    'name': 'John Doe',
    'age': 30,
    'city': 'Example City'
}


def save_data(data, fielpath = 'example.json'):
	with open('example.json', 'w') as json_file:
		json.dump(data, json_file)

